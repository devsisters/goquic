#include "go_quic_dispatcher.h"

#include "go_functions.h"

#include "base/debug/stack_trace.h"
#include "base/logging.h"
#include "base/stl_util.h"
#include "net/quic/crypto/quic_random.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_utils.h"
#include "chlo_extractor.h"
#include "stateless_rejector.h"
#include "go_quic_per_connection_packet_writer.h"
#include "go_quic_time_wait_list_manager.h"
#include "go_quic_server_packet_writer.h"
#include "go_quic_simple_server_session.h"

using std::string;

namespace net {

using std::make_pair;
using base::StringPiece;

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
  ChloValidator(QuicServerSessionBase::Helper* helper,
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
  QuicServerSessionBase::Helper* helper_;  // Unowned.
  IPEndPoint self_address_;
  StatelessRejector* rejector_;  // Unowned.
  bool can_accept_;
  string error_details_;
};

}  // namespace

GoQuicDispatcher::GoQuicDispatcher(
    const QuicConfig& config,
    const QuicCryptoServerConfig* crypto_config,
    const QuicVersionVector& supported_versions,
    std::unique_ptr<QuicConnectionHelperInterface> helper,
    std::unique_ptr<QuicServerSessionBase::Helper> session_helper,
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
      supported_versions_(supported_versions),
      disable_quic_pre_30_(FLAGS_quic_disable_pre_30),
      allowed_supported_versions_(supported_versions),
      current_packet_(nullptr),
      framer_(supported_versions,
              /*unused*/ QuicTime::Zero(),
              Perspective::IS_SERVER),
      last_error_(QUIC_NO_ERROR),
      go_quic_dispatcher_(go_quic_dispatcher) {
  framer_.set_visitor(this);
}

GoQuicDispatcher::~GoQuicDispatcher() {
  STLDeleteValues(&session_map_);
  STLDeleteElements(&closed_session_list_);
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

  // Packet's connection ID is unknown.
  // Apply the validity checks.
  QuicPacketFate fate = ValidityChecks(header);
  if (fate == kFateProcess) {
      fate = MaybeRejectStatelessly(connection_id, header);
  }
  switch (fate) {
    case kFateProcess: {
      // Create a session and process the packet.
      QuicServerSessionBase* session =
          CreateQuicSession(connection_id, current_client_address_);
      DVLOG(1) << "Created new session for " << connection_id;
      session_map_.insert(std::make_pair(connection_id, session));
      session->ProcessUdpPacket(current_server_address_,
                                current_client_address_, *current_packet_);
      std::list<QuicBufferedPacketStore::BufferedPacket> packets =
          buffered_packets_.DeliverPackets(connection_id);
      for (const auto& packet : packets) {
        SessionMap::iterator it = session_map_.find(connection_id);
        if (it == session_map_.end()) {
          break;
        }
        it->second->ProcessUdpPacket(packet.server_address,
                                     packet.client_address, *packet.packet);
      }
      break;
    }
    case kFateTimeWait:
      // MaybeRejectStatelessly might have already added the connection to
      // time wait, in which case it should not be added again.
      if (!FLAGS_quic_use_cheap_stateless_rejects ||
          !time_wait_list_manager_->IsConnectionIdInTimeWait(
              header.public_header.connection_id)) {
        // Add this connection_id to the time-wait state, to safely reject
        // future packets.
        DVLOG(1) << "Adding connection ID " << connection_id
                 << "to time-wait list.";
        time_wait_list_manager_->AddConnectionIdToTimeWait(
            connection_id, framer_.version(),
            /*connection_rejected_statelessly=*/false, nullptr);
      }
      DCHECK(time_wait_list_manager_->IsConnectionIdInTimeWait(
          header.public_header.connection_id));
      time_wait_list_manager_->ProcessPacket(
          current_server_address_, current_client_address_,
          header.public_header.connection_id, header.packet_number,
          *current_packet_);
      break;
    case kFateDrop:
      // Do nothing with the packet.
      break;
  }

  return false;
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
  STLDeleteElements(&closed_session_list_);
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
    delete_sessions_alarm_->Cancel();
    delete_sessions_alarm_->Set(helper_->GetClock()->ApproximateNow());
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
    QuicBufferedPacketStore::BufferedPacketList early_arrived_packets) {}

QuicServerSessionBase* GoQuicDispatcher::CreateQuicSession(
    QuicConnectionId connection_id,
    const IPEndPoint& client_address) {
  // The QuicServerSessionBase takes ownership of |connection| below.
  QuicConnection* connection = new QuicConnection(
      connection_id, client_address, helper_.get(), alarm_factory_.get(),
      CreatePerConnectionWriter(),
      /* owns_writer= */ true, Perspective::IS_SERVER, GetSupportedVersions());

  GoQuicSimpleServerSession* session = new GoQuicSimpleServerSession(
      config_, connection, this, session_helper_.get(), crypto_config_,
      &compressed_certs_cache_);

  session->SetGoSession(go_quic_dispatcher_,
                        GoPtr(CreateGoSession_C(go_quic_dispatcher_, session)));
  session->Initialize();

  // SimpleQuicDispatcher behaviour
  static_cast<GoQuicPerConnectionPacketWriter*>(
      session->connection()->writer())
      ->set_connection(session->connection());
  return session;
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
  // Filter (or un-filter) the list of supported versions based on the flag.
  if (disable_quic_pre_30_ != FLAGS_quic_disable_pre_30) {
    DCHECK_EQ(supported_versions_.capacity(),
              allowed_supported_versions_.capacity());
    disable_quic_pre_30_ = FLAGS_quic_disable_pre_30;
    supported_versions_ = FilterSupportedVersions(allowed_supported_versions_);
  }
  return supported_versions_;
}

GoQuicDispatcher::QuicPacketFate GoQuicDispatcher::MaybeRejectStatelessly(
    QuicConnectionId connection_id,
    const QuicPacketHeader& header) {
  // TODO(rch): This logic should probably live completely inside the rejector.
  if (!FLAGS_quic_use_cheap_stateless_rejects ||
      !FLAGS_enable_quic_stateless_reject_support ||
      header.public_header.versions.front() <= QUIC_VERSION_32 ||
      !ShouldAttemptCheapStatelessRejection()) {
    return kFateProcess;
  }

  StatelessRejector rejector(header.public_header.versions.front(),
                             supported_versions_, crypto_config_,
                             &compressed_certs_cache_, helper()->GetClock(),
                             helper()->GetRandomGenerator(),
                             current_client_address_, current_server_address_);
  ChloValidator validator(session_helper_.get(), current_server_address_,
                          &rejector);
  if (!ChloExtractor::Extract(*current_packet_, supported_versions_,
                              &validator)) {
    DVLOG(1) << "Buffering undecryptable packet.";
    buffered_packets_.EnqueuePacket(connection_id, *current_packet_,
                                    current_server_address_,
                                    current_client_address_);
    return kFateDrop;
  }

  if (!validator.can_accept()) {
    // This CHLO is prohibited by policy.
    StatelessConnectionTerminator terminator(connection_id, &framer_, helper(),
                                             time_wait_list_manager_.get());
    terminator.CloseConnection(QUIC_HANDSHAKE_FAILED,
                               validator.error_details());
    OnConnectionClosedStatelessly(QUIC_HANDSHAKE_FAILED);
    return kFateTimeWait;
  }

  // This packet included a CHLO. See if it can be rejected statelessly.
  switch (rejector.state()) {
    case StatelessRejector::FAILED: {
      // There was an error processing the client hello.
      StatelessConnectionTerminator terminator(
          connection_id, &framer_, helper(), time_wait_list_manager_.get());
      terminator.CloseConnection(rejector.error(), rejector.error_details());
      return kFateTimeWait;
    }

    case StatelessRejector::UNSUPPORTED:
      // Cheap stateless rejects are not supported so process the packet.
      return kFateProcess;

    case StatelessRejector::ACCEPTED:
      // Contains a valid CHLO, so process the packet and create a connection.
      return kFateProcess;

    case StatelessRejector::REJECTED: {
      DCHECK_EQ(framer_.version(), header.public_header.versions.front());
      StatelessConnectionTerminator terminator(
          connection_id, &framer_, helper(), time_wait_list_manager_.get());
      terminator.RejectConnection(
          rejector.reply().GetSerialized().AsStringPiece());
      OnConnectionRejectedStatelessly();
      return kFateTimeWait;
    }
  }

  QUIC_BUG << "Rejector has unknown invalid state.";
  return kFateDrop;
}

}  // namespace net
