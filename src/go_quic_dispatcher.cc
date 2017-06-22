#include "go_quic_dispatcher.h"

#include "go_functions.h"

#include "base/debug/stack_trace.h"
#include "base/logging.h"
#include "base/stl_util.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/quic_bug_tracker.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_utils.h"
#include "chlo_extractor.h"
#include "stateless_rejector.h"
#include "go_quic_per_connection_packet_writer.h"
#include "go_quic_time_wait_list_manager.h"
#include "go_quic_server_packet_writer.h"
#include "go_quic_simple_server_session.h"

using base::StringPiece;
using std::list;
using std::string;

namespace net {

typedef QuicBufferedPacketStore::BufferedPacket BufferedPacket;
typedef QuicBufferedPacketStore::BufferedPacketList BufferedPacketList;
typedef QuicBufferedPacketStore::EnqueuePacketResult EnqueuePacketResult;

namespace {

// An alarm that informs the GoQuicDispatcher to delete old sessions.
class DeleteSessionsAlarm : public QuicAlarm::Delegate {
 public:
  explicit DeleteSessionsAlarm(GoQuicDispatcher* dispatcher)
      : dispatcher_(dispatcher) {}

  void OnAlarm() override { dispatcher_->DeleteSessions(); }

 private:
  // Not owned.
  GoQuicDispatcher* dispatcher_;

  DISALLOW_COPY_AND_ASSIGN(DeleteSessionsAlarm);
};

// Collects packets serialized by a QuicPacketCreator in order
// to be handed off to the time wait list manager.
class PacketCollector : public QuicPacketCreator::DelegateInterface {
 public:
  ~PacketCollector() override {}

  void OnSerializedPacket(SerializedPacket* serialized_packet) override {
    // Make a copy of the serialized packet to send later.
    packets_.push_back(std::unique_ptr<QuicEncryptedPacket>(
        new QuicEncryptedPacket(QuicUtils::CopyBuffer(*serialized_packet),
                                serialized_packet->encrypted_length, true)));
    serialized_packet->encrypted_buffer = nullptr;
    QuicUtils::DeleteFrames(&(serialized_packet->retransmittable_frames));
    serialized_packet->retransmittable_frames.clear();
  }

  void OnUnrecoverableError(QuicErrorCode error,
                            const string& error_details,
                            ConnectionCloseSource source) override {}

  std::vector<std::unique_ptr<QuicEncryptedPacket>>* packets() {
    return &packets_;
  }

 private:
  std::vector<std::unique_ptr<QuicEncryptedPacket>> packets_;
};

// Helper for statelessly closing connections by generating the
// correct termination packets and adding the connection to the time wait
// list manager.
class StatelessConnectionTerminator {
 public:
  StatelessConnectionTerminator(QuicConnectionId connection_id,
                                QuicFramer* framer,
                                QuicConnectionHelperInterface* helper,
                                GoQuicTimeWaitListManager* time_wait_list_manager)
      : connection_id_(connection_id),
        framer_(framer),
        creator_(connection_id,
                 framer,
                 helper->GetRandomGenerator(),
                 helper->GetBufferAllocator(),
                 &collector_),
        time_wait_list_manager_(time_wait_list_manager) {}

  // Generates a packet containing a CONNECTION_CLOSE frame specifying
  // |error_code| and |error_details| and add the connection to time wait.
  void CloseConnection(QuicErrorCode error_code,
                       const std::string& error_details) {
    QuicConnectionCloseFrame* frame = new QuicConnectionCloseFrame;
    frame->error_code = error_code;
    frame->error_details = error_details;
    if (!creator_.AddSavedFrame(QuicFrame(frame))) {
      QUIC_BUG << "Unable to add frame to an empty packet";
      delete frame;
      return;
    }
    creator_.Flush();
    DCHECK_EQ(1u, collector_.packets()->size());
    time_wait_list_manager_->AddConnectionIdToTimeWait(
        connection_id_, framer_->version(),
        /*connection_rejected_statelessly=*/false, collector_.packets());
  }

  // Generates a series of termination packets containing the crypto handshake
  // message |reject|.  Adds the connection to time wait list with the
  // generated packets.
  void RejectConnection(StringPiece reject) {
    struct iovec iovec;
    iovec.iov_base = const_cast<char*>(reject.data());
    iovec.iov_len = reject.length();
    QuicIOVector iov(&iovec, 1, iovec.iov_len);
    QuicStreamOffset offset = 0;
    while (offset < iovec.iov_len) {
      QuicFrame frame;
      UniqueStreamBuffer data;
      if (!creator_.ConsumeData(kCryptoStreamId, iov, offset, offset,
                                /*fin=*/false,
                                /*needs_full_padding=*/true, &frame)) {
        QUIC_BUG << "Unable to consume data into an empty packet.";
        return;
      }
      offset += frame.stream_frame->data_length;
      if (offset < iovec.iov_len) {
        DCHECK(!creator_.HasRoomForStreamFrame(kCryptoStreamId, offset));
      }
      creator_.Flush();
    }
    time_wait_list_manager_->AddConnectionIdToTimeWait(
        connection_id_, framer_->version(),
        /*connection_rejected_statelessly=*/true, collector_.packets());
    DCHECK(time_wait_list_manager_->IsConnectionIdInTimeWait(connection_id_));
  }

 private:
  QuicConnectionId connection_id_;
  QuicFramer* framer_;  // Unowned.
  // Set as the visitor of |creator_| to collect any generated packets.
  PacketCollector collector_;
  QuicPacketCreator creator_;
  GoQuicTimeWaitListManager* time_wait_list_manager_;
};

// Class which sits between the ChloExtractor and the StatelessRejector
// to give the QuicDispatcher a chance to apply policy checks to the CHLO.
class ChloValidator : public ChloExtractor::Delegate {
 public:
  ChloValidator(QuicCryptoServerStream::Helper* helper,
                IPEndPoint self_address,
                StatelessRejector* rejector)
      : helper_(helper),
        self_address_(self_address),
        rejector_(rejector),
        can_accept_(false) {}

  // ChloExtractor::Delegate implementation.
  void OnChlo(QuicVersion version,
              QuicConnectionId connection_id,
              const CryptoHandshakeMessage& chlo) override {
    if (helper_->CanAcceptClientHello(chlo, self_address_, &error_details_)) {
      can_accept_ = true;
      rejector_->OnChlo(version, connection_id,
                        helper_->GenerateConnectionIdForReject(connection_id),
                        chlo);
    }
  }

  bool can_accept() const { return can_accept_; }

  const string& error_details() const { return error_details_; }

 private:
  QuicCryptoServerStream::Helper* helper_;  // Unowned.
  IPEndPoint self_address_;
  StatelessRejector* rejector_;  // Unowned.
  bool can_accept_;
  string error_details_;
};

}  // namespace

GoQuicDispatcher::GoQuicDispatcher(
    const QuicConfig& config,
    const QuicCryptoServerConfig* crypto_config,
    QuicVersionManager* version_manager,
    std::unique_ptr<QuicConnectionHelperInterface> helper,
    std::unique_ptr<QuicCryptoServerStream::Helper> session_helper,
    std::unique_ptr<QuicAlarmFactory> alarm_factory,
    GoPtr go_quic_dispatcher)
    : config_(config),
      crypto_config_(crypto_config),
      compressed_certs_cache_(
          QuicCompressedCertsCache::kQuicCompressedCertsCacheSize),
      helper_(std::move(helper)),
      session_helper_(std::move(session_helper)),
      alarm_factory_(std::move(alarm_factory)),
      delete_sessions_alarm_(
          alarm_factory_->CreateAlarm(new DeleteSessionsAlarm(
          this))),  // alarm's delegate is deleted by std::unique_ptr of QuicAlarm
      buffered_packets_(this, helper_->GetClock(), alarm_factory_.get()),
      current_packet_(nullptr),
      version_manager_(version_manager),
      framer_(GetSupportedVersions(),
              /*unused*/ QuicTime::Zero(),
              Perspective::IS_SERVER),
      last_error_(QUIC_NO_ERROR),
      new_sessions_allowed_per_event_loop_(0u),
      go_quic_dispatcher_(go_quic_dispatcher) {
  framer_.set_visitor(this);
}

GoQuicDispatcher::~GoQuicDispatcher() {
  base::STLDeleteValues(&session_map_);
  base::STLDeleteElements(&closed_session_list_);
  ReleaseQuicDispatcher_C(go_quic_dispatcher_);
}

void GoQuicDispatcher::InitializeWithWriter(QuicPacketWriter* writer) {
  DCHECK(writer_ == nullptr);
  writer_.reset(writer);
  time_wait_list_manager_.reset(CreateQuicTimeWaitListManager());
}

void GoQuicDispatcher::ProcessPacket(const IPEndPoint& server_address,
                                     const IPEndPoint& client_address,
                                     const QuicReceivedPacket& packet) {
  current_server_address_ = server_address;
  current_client_address_ = client_address;
  current_packet_ = &packet;
  // ProcessPacket will cause the packet to be dispatched in
  // OnUnauthenticatedPublicHeader, or sent to the time wait list manager
  // in OnAuthenticatedHeader.
  framer_.ProcessPacket(packet);
  // TODO(rjshade): Return a status describing if/why a packet was dropped,
  //                and log somehow.  Maybe expose as a varz.
}

bool GoQuicDispatcher::OnUnauthenticatedPublicHeader(
    const QuicPacketPublicHeader& header) {
  current_connection_id_ = header.connection_id;

  // Port zero is only allowed for unidirectional UDP, so is disallowed by QUIC.
  // Given that we can't even send a reply rejecting the packet, just black hole
  // it.
  if (current_client_address_.port() == 0) {
    return false;
  }

  // Stopgap test: The code does not construct full-length connection IDs
  // correctly from truncated connection ID fields.  Prevent this from causing
  // the connection ID lookup to error by dropping any packet with a short
  // connection ID.
  if (header.connection_id_length != PACKET_8BYTE_CONNECTION_ID) {
    return false;
  }

  // Packets with connection IDs for active connections are processed
  // immediately.
  QuicConnectionId connection_id = header.connection_id;
  SessionMap::iterator it = session_map_.find(connection_id);
  if (it != session_map_.end()) {
    DCHECK(!buffered_packets_.HasBufferedPackets(connection_id));
    it->second->ProcessUdpPacket(current_server_address_,
                                 current_client_address_, *current_packet_);
    return false;
  }

  if (!OnUnauthenticatedUnknownPublicHeader(header)) {
    return false;
  }

  // If the packet is a public reset for a connection ID that is not active,
  // there is nothing we must do or can do.
  if (header.reset_flag) {
    return false;
  }

  if (time_wait_list_manager_->IsConnectionIdInTimeWait(connection_id)) {
    // Set the framer's version based on the recorded version for this
    // connection and continue processing for non-public-reset packets.
    return HandlePacketForTimeWait(header);
  }

  // The packet has an unknown connection ID.

  // Unless the packet provides a version, assume that we can continue
  // processing using our preferred version.
  QuicVersion version = GetSupportedVersions().front();
  if (header.version_flag) {
    QuicVersion packet_version = header.versions.front();
    if (!framer_.IsSupportedVersion(packet_version)) {
      if (ShouldCreateSessionForUnknownVersion(framer_.last_version_tag())) {
        return true;
      }
      // Since the version is not supported, send a version negotiation
      // packet and stop processing the current packet.
      time_wait_list_manager()->SendVersionNegotiationPacket(
          connection_id, GetSupportedVersions(), current_server_address_,
          current_client_address_);
      return false;
    }
    version = packet_version;
  }
  // Set the framer's version and continue processing.
  framer_.set_version(version);
  return true;
}

bool GoQuicDispatcher::OnUnauthenticatedHeader(const QuicPacketHeader& header) {
  QuicConnectionId connection_id = header.public_header.connection_id;

  if (time_wait_list_manager_->IsConnectionIdInTimeWait(
          header.public_header.connection_id)) {
    // This connection ID is already in time-wait state.
    time_wait_list_manager_->ProcessPacket(
        current_server_address_, current_client_address_,
        header.public_header.connection_id, header.packet_number,
        *current_packet_);
    return false;
  }

  // Packet's connection ID is unknown.  Apply the validity checks.
  QuicPacketFate fate = ValidityChecks(header);
  if (fate == kFateProcess) {
    // Execute stateless rejection logic to determine the packet fate, then
    // invoke ProcessUnauthenticatedHeaderFate.
    MaybeRejectStatelessly(connection_id, header);
  } else {
    // If the fate is already known, process it without executing stateless
    // rejection logic.
    ProcessUnauthenticatedHeaderFate(fate, connection_id, header.packet_number);
  }

  return false;
}

void GoQuicDispatcher::ProcessUnauthenticatedHeaderFate(
    QuicPacketFate fate,
    QuicConnectionId connection_id,
    QuicPacketNumber packet_number) {
  switch (fate) {
    case kFateProcess: {
      ProcessChlo();
      break;
    }
    case kFateTimeWait:
      // MaybeRejectStatelessly might have already added the connection to
      // time wait, in which case it should not be added again.
      if (!FLAGS_quic_use_cheap_stateless_rejects ||
          !time_wait_list_manager_->IsConnectionIdInTimeWait(connection_id)) {
        // Add this connection_id to the time-wait state, to safely reject
        // future packets.
        DVLOG(1) << "Adding connection ID " << connection_id
                 << "to time-wait list.";
        time_wait_list_manager_->AddConnectionIdToTimeWait(
            connection_id, framer_.version(),
            /*connection_rejected_statelessly=*/false, nullptr);
      }
      DCHECK(time_wait_list_manager_->IsConnectionIdInTimeWait(connection_id));
      time_wait_list_manager_->ProcessPacket(
          current_server_address_, current_client_address_, connection_id,
          packet_number, *current_packet_);
      break;
    case kFateBuffer:
      // This packet is a non-CHLO packet which has arrived out of order.
      // Buffer it.
      BufferEarlyPacket(connection_id);
      break;
    case kFateDrop:
      // Do nothing with the packet.
      break;
  }
}

GoQuicDispatcher::QuicPacketFate GoQuicDispatcher::ValidityChecks(
    const QuicPacketHeader& header) {
  // To have all the checks work properly without tears, insert any new check
  // into the framework of this method in the section for checks that return the
  // check's fate value.  The sections for checks must be ordered with the
  // highest priority fate first.

  // Checks that return kFateDrop.

  // Checks that return kFateTimeWait.

  // All packets within a connection sent by a client before receiving a
  // response from the server are required to have the version negotiation flag
  // set.  Since this may be a client continuing a connection we lost track of
  // via server restart, send a rejection to fast-fail the connection.
  if (!header.public_header.version_flag) {
    DVLOG(1) << "Packet without version arrived for unknown connection ID "
             << header.public_header.connection_id;
    return kFateTimeWait;
  }

  // Check that the sequence numer is within the range that the client is
  // expected to send before receiving a response from the server.
  if (header.packet_number == kInvalidPacketNumber ||
      header.packet_number > kMaxReasonableInitialPacketNumber) {
    return kFateTimeWait;
  }

  return kFateProcess;
}

void GoQuicDispatcher::CleanUpSession(SessionMap::iterator it,
                                      bool should_close_statelessly) {
  QuicConnection* connection = it->second->connection();

  write_blocked_list_.erase(connection);
  if (should_close_statelessly) {
    DCHECK(connection->termination_packets() != nullptr &&
           !connection->termination_packets()->empty());
  }
  time_wait_list_manager_->AddConnectionIdToTimeWait(
      it->first, connection->version(), should_close_statelessly,
      connection->termination_packets());
  session_map_.erase(it);
}

void GoQuicDispatcher::DeleteSessions() {
  base::STLDeleteElements(&closed_session_list_);
}

void GoQuicDispatcher::OnCanWrite() {
  // We finished a write: the socket should not be blocked.
  writer_->SetWritable();

  // Give all the blocked writers one chance to write, until we're blocked again
  // or there's no work left.
  while (!write_blocked_list_.empty() && !writer_->IsWriteBlocked()) {
    QuicBlockedWriterInterface* blocked_writer =
        write_blocked_list_.begin()->first;
    write_blocked_list_.erase(write_blocked_list_.begin());
    blocked_writer->OnCanWrite();
  }
}

bool GoQuicDispatcher::HasPendingWrites() const {
  return !write_blocked_list_.empty();
}

void GoQuicDispatcher::Shutdown() {
  while (!session_map_.empty()) {
    QuicServerSessionBase* session = session_map_.begin()->second;
    session->connection()->CloseConnection(
        QUIC_PEER_GOING_AWAY, "Server shutdown imminent",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    // Validate that the session removes itself from the session map on close.
    DCHECK(session_map_.empty() || session_map_.begin()->second != session);
  }
  DeleteSessions();
}

void GoQuicDispatcher::OnConnectionClosed(QuicConnectionId connection_id,
                                          QuicErrorCode error,
                                          const string& error_details) {
  SessionMap::iterator it = session_map_.find(connection_id);
  if (it == session_map_.end()) {
    QUIC_BUG << "ConnectionId " << connection_id
             << " does not exist in the session map.  Error: "
             << QuicUtils::ErrorToString(error);
    QUIC_BUG << base::debug::StackTrace().ToString();
    return;
  }

  DVLOG_IF(1, error != QUIC_NO_ERROR)
      << "Closing connection (" << connection_id
      << ") due to error: " << QuicUtils::ErrorToString(error)
      << ", with details: " << error_details;

  if (closed_session_list_.empty()) {
    delete_sessions_alarm_->Update(helper_->GetClock()->ApproximateNow(),
                                   QuicTime::Delta::Zero());
  }
  closed_session_list_.push_back(it->second);
  const bool should_close_statelessly =
      (error == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT);
  CleanUpSession(it, should_close_statelessly);
}

void GoQuicDispatcher::OnWriteBlocked(
    QuicBlockedWriterInterface* blocked_writer) {
  if (!writer_->IsWriteBlocked()) {
    QUIC_BUG << "QuicDispatcher::OnWriteBlocked called when the writer is "
                "not blocked.";
    // Return without adding the connection to the blocked list, to avoid
    // infinite loops in OnCanWrite.
    return;
  }
  write_blocked_list_.insert(std::make_pair(blocked_writer, true));
}

void GoQuicDispatcher::OnConnectionAddedToTimeWaitList(
    QuicConnectionId connection_id) {
  DVLOG(1) << "Connection " << connection_id << " added to time wait list.";
}

void GoQuicDispatcher::OnPacket() {}

void GoQuicDispatcher::OnError(QuicFramer* framer) {
  QuicErrorCode error = framer->error();
  SetLastError(error);
  DVLOG(1) << QuicUtils::ErrorToString(error);
}

bool GoQuicDispatcher::ShouldCreateSessionForUnknownVersion(QuicTag version_tag) {
  return false;
}

bool GoQuicDispatcher::OnProtocolVersionMismatch(
    QuicVersion /*received_version*/) {
  QUIC_BUG_IF(!time_wait_list_manager_->IsConnectionIdInTimeWait(
                  current_connection_id_) &&
              !ShouldCreateSessionForUnknownVersion(framer_.last_version_tag()))
      << "Unexpected version mismatch: "
      << QuicUtils::TagToString(framer_.last_version_tag());

  // Keep processing after protocol mismatch - this will be dealt with by the
  // time wait list or connection that we will create.
  return true;
}

void GoQuicDispatcher::OnPublicResetPacket(
    const QuicPublicResetPacket& /*packet*/) {
  DCHECK(false);
}

void GoQuicDispatcher::OnVersionNegotiationPacket(
    const QuicVersionNegotiationPacket& /*packet*/) {
  DCHECK(false);
}

void GoQuicDispatcher::OnDecryptedPacket(EncryptionLevel level) {
  DCHECK(false);
}

bool GoQuicDispatcher::OnPacketHeader(const QuicPacketHeader& /*header*/) {
  DCHECK(false);
  return false;
}

bool GoQuicDispatcher::OnStreamFrame(const QuicStreamFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool GoQuicDispatcher::OnAckFrame(const QuicAckFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool GoQuicDispatcher::OnStopWaitingFrame(const QuicStopWaitingFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool GoQuicDispatcher::OnPaddingFrame(const QuicPaddingFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool GoQuicDispatcher::OnPingFrame(const QuicPingFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool GoQuicDispatcher::OnRstStreamFrame(const QuicRstStreamFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool GoQuicDispatcher::OnConnectionCloseFrame(
    const QuicConnectionCloseFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool GoQuicDispatcher::OnGoAwayFrame(const QuicGoAwayFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool GoQuicDispatcher::OnWindowUpdateFrame(
    const QuicWindowUpdateFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool GoQuicDispatcher::OnBlockedFrame(const QuicBlockedFrame& frame) {
  DCHECK(false);
  return false;
}

bool GoQuicDispatcher::OnPathCloseFrame(const QuicPathCloseFrame& frame) {
  DCHECK(false);
  return false;
}

void GoQuicDispatcher::OnPacketComplete() {
  DCHECK(false);
}

void GoQuicDispatcher::OnExpiredPackets(
    QuicConnectionId connection_id,
    BufferedPacketList early_arrived_packets) {
  time_wait_list_manager_->AddConnectionIdToTimeWait(
      connection_id, framer_.version(), false, nullptr);
}

void GoQuicDispatcher::ProcessBufferedChlos(size_t max_connections_to_create) {
  // Reset the counter before starting creating connections.
  new_sessions_allowed_per_event_loop_ = max_connections_to_create;
  for (; new_sessions_allowed_per_event_loop_ > 0;
       --new_sessions_allowed_per_event_loop_) {
    QuicConnectionId connection_id;
    list<BufferedPacket> packets =
        buffered_packets_.DeliverPacketsForNextConnection(&connection_id);
    if (packets.empty()) {
      return;
    }
    QuicServerSessionBase* session =
        CreateQuicSession(connection_id, packets.front().client_address);
    DVLOG(1) << "Created new session for " << connection_id;
    session_map_.insert(std::make_pair(connection_id, session));
    DeliverPacketsToSession(packets, session);
  }
}

bool GoQuicDispatcher::HasChlosBuffered() const {
  return buffered_packets_.HasChlosBuffered();
}

void GoQuicDispatcher::OnNewConnectionAdded(QuicConnectionId connection_id) {
  VLOG(1) << "Received packet from new connection " << connection_id;
}

// Return true if there is any packet buffered in the store.
bool GoQuicDispatcher::HasBufferedPackets(QuicConnectionId connection_id) {
  return buffered_packets_.HasBufferedPackets(connection_id);
}

void GoQuicDispatcher::OnBufferPacketFailure(EnqueuePacketResult result,
                                           QuicConnectionId connection_id) {
  DVLOG(1) << "Fail to buffer packet on connection " << connection_id
           << " because of " << result;
}

void GoQuicDispatcher::OnConnectionRejectedStatelessly() {}

void GoQuicDispatcher::OnConnectionClosedStatelessly(QuicErrorCode error) {}

bool GoQuicDispatcher::ShouldAttemptCheapStatelessRejection() {
  return true;
}


GoQuicTimeWaitListManager* GoQuicDispatcher::CreateQuicTimeWaitListManager() {
  // Deleted by caller's std::unique_ptr
  return new GoQuicTimeWaitListManager(writer_.get(), this, helper_.get(),
                                       alarm_factory_.get());
}

void GoQuicDispatcher::BufferEarlyPacket(QuicConnectionId connection_id) {
  bool is_new_connection = !buffered_packets_.HasBufferedPackets(connection_id);
  EnqueuePacketResult rs = buffered_packets_.EnqueuePacket(
      connection_id, *current_packet_, current_server_address_,
      current_client_address_, /*is_chlo=*/false);
  if (rs != EnqueuePacketResult::SUCCESS) {
    OnBufferPacketFailure(rs, connection_id);
  } else if (is_new_connection) {
    OnNewConnectionAdded(connection_id);
  }
}

void GoQuicDispatcher::ProcessChlo() {

  QUIC_BUG_IF(!FLAGS_quic_buffer_packet_till_chlo &&
              FLAGS_quic_limit_num_new_sessions_per_epoll_loop)
      << "Try to limit connection creation per epoll event while not "
         "supporting packet buffer. "
         "--quic_limit_num_new_sessions_per_epoll_loop = true "
         "--quic_buffer_packet_till_chlo = false";

  if (FLAGS_quic_limit_num_new_sessions_per_epoll_loop &&
      FLAGS_quic_buffer_packet_till_chlo &&
      new_sessions_allowed_per_event_loop_ <= 0) {
    // Can't create new session any more. Wait till next event loop.
    if (!buffered_packets_.HasChloForConnection(current_connection_id_)) {
      // Only buffer one CHLO per connection.
      bool is_new_connection =
          !buffered_packets_.HasBufferedPackets(current_connection_id_);
      EnqueuePacketResult rs = buffered_packets_.EnqueuePacket(
          current_connection_id_, *current_packet_, current_server_address_,
          current_client_address_, /*is_chlo=*/true);
      if (rs != EnqueuePacketResult::SUCCESS) {
        OnBufferPacketFailure(rs, current_connection_id_);
      } else if (is_new_connection) {
        OnNewConnectionAdded(current_connection_id_);
      }
    }
    return;
  }

  // Creates a new session and process all buffered packets for this connection.
  QuicServerSessionBase* session =
      CreateQuicSession(current_connection_id_, current_client_address_);
  if (FLAGS_quic_enforce_mtu_limit &&
      current_packet().potentially_small_mtu()) {
    session->connection()->set_largest_packet_size_supported(
        kMinimumSupportedPacketSize);
  }
  DVLOG(1) << "Created new session for " << current_connection_id_;
  session_map_.insert(std::make_pair(current_connection_id_, session));
  std::list<BufferedPacket> packets =
      buffered_packets_.DeliverPackets(current_connection_id_);
  // Check if CHLO is the first packet arrived on this connection.
  if (FLAGS_quic_buffer_packet_till_chlo && packets.empty()) {
    OnNewConnectionAdded(current_connection_id_);
  }
  // Process CHLO at first.
  session->ProcessUdpPacket(current_server_address_, current_client_address_,
                            *current_packet_);

  // Deliver queued-up packets in the same order as they arrived.
  // Do this even when flag is off because there might be still some packets
  // buffered in the store before flag is turned off.
  DeliverPacketsToSession(packets, session);
  if (FLAGS_quic_limit_num_new_sessions_per_epoll_loop &&
      FLAGS_quic_buffer_packet_till_chlo) {
    --new_sessions_allowed_per_event_loop_;
  }
}

bool GoQuicDispatcher::HandlePacketForTimeWait(
    const QuicPacketPublicHeader& header) {
  if (header.reset_flag) {
    // Public reset packets do not have sequence numbers, so ignore the packet.
    return false;
  }

  // Switch the framer to the correct version, so that the sequence number can
  // be parsed correctly.
  framer_.set_version(time_wait_list_manager_->GetQuicVersionFromConnectionId(
      header.connection_id));

  // Continue parsing the packet to extract the sequence number.  Then
  // send it to the time wait manager in OnUnathenticatedHeader.
  return true;
}

QuicPacketWriter* GoQuicDispatcher::CreatePerConnectionWriter() {
  return new GoQuicPerConnectionPacketWriter(
      static_cast<GoQuicServerPacketWriter*>(writer()));
}

void GoQuicDispatcher::SetLastError(QuicErrorCode error) {
  last_error_ = error;
}

bool GoQuicDispatcher::OnUnauthenticatedUnknownPublicHeader(
    const QuicPacketPublicHeader& header) {
  return true;
}

const QuicVersionVector& GoQuicDispatcher::GetSupportedVersions() {
  return version_manager_->GetSupportedVersions();
}

class StatelessRejectorProcessDoneCallback
    : public StatelessRejector::ProcessDoneCallback {
 public:
  StatelessRejectorProcessDoneCallback(GoQuicDispatcher* dispatcher,
                                       QuicPacketNumber packet_number,
                                       QuicVersion first_version)
      : dispatcher_(dispatcher),
        packet_number_(packet_number),
        first_version_(first_version) {}

  void Run(std::unique_ptr<StatelessRejector> rejector) override {
    dispatcher_->OnStatelessRejectorProcessDone(std::move(rejector),
                                                packet_number_, first_version_);
  }

 private:
  GoQuicDispatcher* dispatcher_;
  QuicPacketNumber packet_number_;
  QuicVersion first_version_;
};

void GoQuicDispatcher::MaybeRejectStatelessly(QuicConnectionId connection_id,
                                            const QuicPacketHeader& header) {
  // TODO(rch): This logic should probably live completely inside the rejector.
  if (!FLAGS_quic_use_cheap_stateless_rejects ||
      !FLAGS_enable_quic_stateless_reject_support ||
      header.public_header.versions.front() <= QUIC_VERSION_32 ||
      !ShouldAttemptCheapStatelessRejection()) {
    // Not use cheap stateless reject.
    if (FLAGS_quic_buffer_packet_till_chlo &&
        !ChloExtractor::Extract(*current_packet_, GetSupportedVersions(),
                                nullptr)) {
      // Buffer non-CHLO packets.
      ProcessUnauthenticatedHeaderFate(kFateBuffer, connection_id,
                                       header.packet_number);
      return;
    }
    ProcessUnauthenticatedHeaderFate(kFateProcess, connection_id,
                                     header.packet_number);
    return;
  }

  std::unique_ptr<StatelessRejector> rejector(new StatelessRejector(
      header.public_header.versions.front(), GetSupportedVersions(),
      crypto_config_, &compressed_certs_cache_, helper()->GetClock(),
      helper()->GetRandomGenerator(), current_packet_->length(),
      current_client_address_, current_server_address_));
  ChloValidator validator(session_helper_.get(), current_server_address_,
                          rejector.get());
  if (!ChloExtractor::Extract(*current_packet_, GetSupportedVersions(),
                              &validator)) {
    if (!FLAGS_quic_buffer_packet_till_chlo) {
      QUIC_BUG
          << "Have to drop packet because buffering non-chlo packet is "
             "not supported while trying to do stateless reject. "
             "--gfe2_reloadable_flag_quic_buffer_packet_till_chlo false"
             " --gfe2_reloadable_flag_quic_use_cheap_stateless_rejects true";
      ProcessUnauthenticatedHeaderFate(kFateDrop, connection_id,
                                       header.packet_number);
      return;
    }
    ProcessUnauthenticatedHeaderFate(kFateDrop, connection_id,
                                     header.packet_number);
    return;
  }

  if (!validator.can_accept()) {
    // This CHLO is prohibited by policy.
    StatelessConnectionTerminator terminator(connection_id, &framer_, helper(),
                                             time_wait_list_manager_.get());
    terminator.CloseConnection(QUIC_HANDSHAKE_FAILED,
                               validator.error_details());
    OnConnectionClosedStatelessly(QUIC_HANDSHAKE_FAILED);
    ProcessUnauthenticatedHeaderFate(kFateTimeWait, connection_id,
                                 header.packet_number);
    return;
  }

  // Continue stateless rejector processing
  std::unique_ptr<StatelessRejectorProcessDoneCallback> cb(
      new StatelessRejectorProcessDoneCallback(
          this, header.packet_number, header.public_header.versions.front()));
  StatelessRejector::Process(std::move(rejector), std::move(cb));
}

void GoQuicDispatcher::OnStatelessRejectorProcessDone(
    std::unique_ptr<StatelessRejector> rejector,
    QuicPacketNumber packet_number,
    QuicVersion first_version) {
  QuicPacketFate fate;
  switch (rejector->state()) {
    case StatelessRejector::FAILED: {
      // There was an error processing the client hello.
      StatelessConnectionTerminator terminator(rejector->connection_id(),
                                               &framer_, helper(),
                                               time_wait_list_manager_.get());
      terminator.CloseConnection(rejector->error(), rejector->error_details());
      fate = kFateTimeWait;
      break;
    }

    case StatelessRejector::UNSUPPORTED:
      // Cheap stateless rejects are not supported so process the packet.
      fate = kFateProcess;
      break;

    case StatelessRejector::ACCEPTED:
      // Contains a valid CHLO, so process the packet and create a connection.
      fate = kFateProcess;
      break;

    case StatelessRejector::REJECTED: {
      DCHECK_EQ(framer_.version(), first_version);
      StatelessConnectionTerminator terminator(rejector->connection_id(),
                                               &framer_, helper(),
                                               time_wait_list_manager_.get());
      terminator.RejectConnection(
          rejector->reply().GetSerialized().AsStringPiece());
      OnConnectionRejectedStatelessly();
      fate = kFateTimeWait;
      break;
    }

    default:
      QUIC_BUG << "Rejector has invalid state " << rejector->state();
      fate = kFateDrop;
      break;
  }
  ProcessUnauthenticatedHeaderFate(fate, rejector->connection_id(),
                                   packet_number);
}

void GoQuicDispatcher::DeliverPacketsToSession(
    const std::list<BufferedPacket>& packets,
    QuicServerSessionBase* session) {
  for (const BufferedPacket& packet : packets) {
    session->ProcessUdpPacket(packet.server_address, packet.client_address,
                              *(packet.packet));
  }
}

}  // namespace net
