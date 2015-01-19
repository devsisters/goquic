#include "go_quic_dispatcher.h"

#include "go_quic_time_wait_list_manager.h"
#include "go_quic_per_connection_packet_writer.h"

#include "base/debug/stack_trace.h"
#include "base/logging.h"
#include "base/stl_util.h"
#include "net/quic/quic_blocked_writer_interface.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_utils.h"

namespace net {

using base::StringPiece;
using std::make_pair;
using std::find;

class DeleteSessionsAlarm : public QuicAlarm::Delegate {
 public:
  explicit DeleteSessionsAlarm(GoQuicDispatcher* dispatcher)
      : dispatcher_(dispatcher) {
  }

  QuicTime OnAlarm() override {
    dispatcher_->DeleteSessions();
    return QuicTime::Zero();
  }

 private:
  GoQuicDispatcher* dispatcher_;
};

class GoQuicDispatcher::QuicFramerVisitor : public QuicFramerVisitorInterface {
 public:
  explicit QuicFramerVisitor(GoQuicDispatcher* dispatcher)
      : dispatcher_(dispatcher),
        connection_id_(0) {}

  // QuicFramerVisitorInterface implementation
  void OnPacket() override {}
  bool OnUnauthenticatedPublicHeader(
      const QuicPacketPublicHeader& header) override {
    connection_id_ = header.connection_id;
    return dispatcher_->OnUnauthenticatedPublicHeader(header);
  }
  bool OnUnauthenticatedHeader(const QuicPacketHeader& header) override {
    dispatcher_->OnUnauthenticatedHeader(header);
    return false;
  }
  void OnError(QuicFramer* framer) override {
    DVLOG(1) << QuicUtils::ErrorToString(framer->error());
  }

  bool OnProtocolVersionMismatch(QuicVersion /*received_version*/) override {
    if (dispatcher_->time_wait_list_manager()->IsConnectionIdInTimeWait(
            connection_id_)) {
      // Keep processing after protocol mismatch - this will be dealt with by
      // the TimeWaitListManager.
      return true;
    } else {
      DLOG(DFATAL) << "Version mismatch, connection ID (" << connection_id_
                   << ") not in time wait list.";
      return false;
    }
  }

  // The following methods should never get called because we always return
  // false from OnUnauthenticatedHeader().  As a result, we never process the
  // payload of the packet.
  void OnPublicResetPacket(const QuicPublicResetPacket& /*packet*/) override {
    DCHECK(false);
  }
  void OnVersionNegotiationPacket(
      const QuicVersionNegotiationPacket& /*packet*/) override {
    DCHECK(false);
  }
  void OnDecryptedPacket(EncryptionLevel level) override { DCHECK(false); }
  bool OnPacketHeader(const QuicPacketHeader& /*header*/) override {
    DCHECK(false);
    return false;
  }
  void OnRevivedPacket() override { DCHECK(false); }
  void OnFecProtectedPayload(StringPiece /*payload*/) override {
    DCHECK(false);
  }
  bool OnStreamFrame(const QuicStreamFrame& /*frame*/) override {
    DCHECK(false);
    return false;
  }
  bool OnAckFrame(const QuicAckFrame& /*frame*/) override {
    DCHECK(false);
    return false;
  }
  bool OnCongestionFeedbackFrame(
      const QuicCongestionFeedbackFrame& /*frame*/) override {
    DCHECK(false);
    return false;
  }
  bool OnStopWaitingFrame(const QuicStopWaitingFrame& /*frame*/) override {
    DCHECK(false);
    return false;
  }
  bool OnPingFrame(const QuicPingFrame& /*frame*/) override {
    DCHECK(false);
    return false;
  }
  bool OnRstStreamFrame(const QuicRstStreamFrame& /*frame*/) override {
    DCHECK(false);
    return false;
  }
  bool OnConnectionCloseFrame(
      const QuicConnectionCloseFrame& /*frame*/) override {
    DCHECK(false);
    return false;
  }
  bool OnGoAwayFrame(const QuicGoAwayFrame& /*frame*/) override {
    DCHECK(false);
    return false;
  }
  bool OnWindowUpdateFrame(const QuicWindowUpdateFrame& /*frame*/) override {
    DCHECK(false);
    return false;
  }
  bool OnBlockedFrame(const QuicBlockedFrame& frame) override {
    DCHECK(false);
    return false;
  }
  void OnFecData(const QuicFecData& /*fec*/) override { DCHECK(false); }
  void OnPacketComplete() override { DCHECK(false); }

 private:
  GoQuicDispatcher* dispatcher_;

  // Latched in OnUnauthenticatedPublicHeader for use later.
  QuicConnectionId connection_id_;
};

QuicPacketWriter* GoQuicDispatcher::DefaultPacketWriterFactory::Create(
    GoQuicServerPacketWriter* writer,
    QuicConnection* connection) {
  return new GoQuicPerConnectionPacketWriter(writer, connection);
}

GoQuicDispatcher::PacketWriterFactoryAdapter::PacketWriterFactoryAdapter(
    GoQuicDispatcher* dispatcher)
    : dispatcher_(dispatcher) {}

GoQuicDispatcher::PacketWriterFactoryAdapter::~PacketWriterFactoryAdapter() {}

QuicPacketWriter* GoQuicDispatcher::PacketWriterFactoryAdapter::Create(
    QuicConnection* connection) const {
  return dispatcher_->packet_writer_factory_->Create(
      dispatcher_->writer_.get(),
      connection);
}

GoQuicDispatcher::GoQuicDispatcher(const QuicConfig& config,
                                   const QuicCryptoServerConfig& crypto_config,
                                   const QuicVersionVector& supported_versions,
                                   PacketWriterFactory* packet_writer_factory,
                                   QuicConnectionHelperInterface* helper)
    : config_(config),
      crypto_config_(crypto_config),
      helper_(helper),
      delete_sessions_alarm_(
          helper_->CreateAlarm(new DeleteSessionsAlarm(this))),
      packet_writer_factory_(packet_writer_factory),
      connection_writer_factory_(this),
      supported_versions_(supported_versions),
      current_packet_(nullptr),
      framer_(supported_versions, /*unused*/ QuicTime::Zero(), true),
      framer_visitor_(new QuicFramerVisitor(this)) {
  framer_.set_visitor(framer_visitor_.get());
}

GoQuicDispatcher::~GoQuicDispatcher() {
  STLDeleteValues(&session_map_);
  STLDeleteElements(&closed_session_list_);
}

void GoQuicDispatcher::Initialize(GoQuicServerPacketWriter* writer) {
  DCHECK(writer_ == nullptr);
  writer_.reset(writer);
  time_wait_list_manager_.reset(CreateQuicTimeWaitListManager());
}

void GoQuicDispatcher::ProcessPacket(const IPEndPoint& server_address,
                                     const IPEndPoint& client_address,
                                     const QuicEncryptedPacket& packet) {
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
  QuicSession* session = nullptr;

  QuicConnectionId connection_id = header.connection_id;
  SessionMap::iterator it = session_map_.find(connection_id);
  if (it == session_map_.end()) {
    if (header.reset_flag) {
      return false;
    }
    if (time_wait_list_manager_->IsConnectionIdInTimeWait(connection_id)) {
      return HandlePacketForTimeWait(header);
    }

    // Ensure the packet has a version negotiation bit set before creating a new
    // session for it.  All initial packets for a new connection are required to
    // have the flag set.  Otherwise it may be a stray packet.
    if (header.version_flag) {
      session = CreateQuicSession(connection_id, current_server_address_,
                                  current_client_address_);
    }

    if (session == nullptr) {
      DVLOG(1) << "Failed to create session for " << connection_id;
      // Add this connection_id fo the time-wait state, to safely reject future
      // packets.

      if (header.version_flag &&
          !framer_.IsSupportedVersion(header.versions.front())) {
        // TODO(ianswett): Produce a no-version version negotiation packet.
        return false;
      }

      // Use the version in the packet if possible, otherwise assume the latest.
      QuicVersion version = header.version_flag ? header.versions.front() :
          supported_versions_.front();
      time_wait_list_manager_->AddConnectionIdToTimeWait(connection_id, version,
                                                         nullptr);
      DCHECK(time_wait_list_manager_->IsConnectionIdInTimeWait(connection_id));
      return HandlePacketForTimeWait(header);
    }
    DVLOG(1) << "Created new session for " << connection_id;
    session_map_.insert(make_pair(connection_id, session));
  } else {
    session = it->second;
  }

  session->connection()->ProcessUdpPacket(
      current_server_address_, current_client_address_, *current_packet_);

  // Do not parse the packet further.  The session will process it completely.
  return false;
}

void GoQuicDispatcher::OnUnauthenticatedHeader(const QuicPacketHeader& header) {
  DCHECK(time_wait_list_manager_->IsConnectionIdInTimeWait(
      header.public_header.connection_id));
  time_wait_list_manager_->ProcessPacket(current_server_address_,
                                         current_client_address_,
                                         header.public_header.connection_id,
                                         header.packet_sequence_number,
                                         *current_packet_);
}

void GoQuicDispatcher::CleanUpSession(SessionMap::iterator it) {
  QuicConnection* connection = it->second->connection();
  QuicEncryptedPacket* connection_close_packet =
      connection->ReleaseConnectionClosePacket();
  write_blocked_list_.erase(connection);
  time_wait_list_manager_->AddConnectionIdToTimeWait(it->first,
                                                     connection->version(),
                                                     connection_close_packet);
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
    QuicSession* session = session_map_.begin()->second;
    session->connection()->SendConnectionClose(QUIC_PEER_GOING_AWAY);
    // Validate that the session removes itself from the session map on close.
    DCHECK(session_map_.empty() || session_map_.begin()->second != session);
  }
  DeleteSessions();
}

void GoQuicDispatcher::OnConnectionClosed(QuicConnectionId connection_id,
                                          QuicErrorCode error) {
  SessionMap::iterator it = session_map_.find(connection_id);
  if (it == session_map_.end()) {
    LOG(DFATAL) << "ConnectionId " << connection_id
                << " does not exist in the session map.  "
                << "Error: " << QuicUtils::ErrorToString(error);
    LOG(DFATAL) << base::debug::StackTrace().ToString();
    return;
  }
  DVLOG_IF(1, error != QUIC_NO_ERROR) << "Closing connection ("
                                      << connection_id
                                      << ") due to error: "
                                      << QuicUtils::ErrorToString(error);
  if (closed_session_list_.empty()) {
    delete_sessions_alarm_->Set(helper_->GetClock()->ApproximateNow());
  }
  closed_session_list_.push_back(it->second);
  CleanUpSession(it);
}

void GoQuicDispatcher::OnWriteBlocked(
    QuicBlockedWriterInterface* blocked_writer) {
  if (!writer_->IsWriteBlocked()) {
    LOG(DFATAL) <<
        "QuicDispatcher::OnWriteBlocked called when the writer is not blocked.";
    // Return without adding the connection to the blocked list, to avoid
    // infinite loops in OnCanWrite.
    return;
  }
  write_blocked_list_.insert(make_pair(blocked_writer, true));
}

void GoQuicDispatcher::OnConnectionAddedToTimeWaitList(
    QuicConnectionId connection_id) {
  DVLOG(1) << "Connection " << connection_id << " added to time wait list.";
}

void GoQuicDispatcher::OnConnectionRemovedFromTimeWaitList(
    QuicConnectionId connection_id) {
  DVLOG(1) << "Connection " << connection_id << " removed from time wait list.";
}

QuicSession* GoQuicDispatcher::CreateQuicSession(
    QuicConnectionId connection_id,
    const IPEndPoint& server_address,
    const IPEndPoint& client_address) {
  GoQuicServerSession* session = new GoQuicServerSession(
      config_,
      CreateQuicConnection(connection_id, server_address, client_address),
      this);
  session->InitializeSession(crypto_config_);
  return session;
}

QuicConnection* GoQuicDispatcher::CreateQuicConnection(
    QuicConnectionId connection_id,
    const IPEndPoint& server_address,
    const IPEndPoint& client_address) {
  return new QuicConnection(connection_id,
                            client_address,
                            helper_,
                            connection_writer_factory_,
                            /* owns_writer= */ true,
                            /* is_server= */ true,
                            crypto_config_.HasProofSource(),
                            supported_versions_);
}

GoQuicTimeWaitListManager* GoQuicDispatcher::CreateQuicTimeWaitListManager() {
  return new GoQuicTimeWaitListManager(
      writer_.get(), this, helper_, supported_versions());
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

} // namespace net
