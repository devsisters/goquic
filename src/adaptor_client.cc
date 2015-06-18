#include "adaptor_client.h"

#include "go_quic_client_session.h"
#include "go_quic_reliable_client_stream.h"
#include "go_quic_client_packet_writer.h"
#include "go_quic_connection_helper.h"

#include "net/base/ip_endpoint.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/crypto/quic_random.h"
#include "base/strings/string_piece.h"

using namespace net;
using namespace std;
using base::StringPiece;


class GoQuicPacketWriterFactory : public QuicConnection::PacketWriterFactory {
 public:
  explicit GoQuicPacketWriterFactory(QuicPacketWriter* writer) {
//    ON_CALL(*this, Create(_)).WillByDefault(Return(writer));
    writer_ = writer;
  }
  virtual ~GoQuicPacketWriterFactory() override {}

  virtual QuicPacketWriter *Create(QuicConnection* connection) const override {
    return writer_;
  }

 private:
  QuicPacketWriter *writer_;
};


GoQuicClientSession* create_go_quic_client_session_and_initialize(void* go_udp_conn, void* task_runner, IPEndPoint* server_address) {
  QuicConfig config = QuicConfig();
  QuicClock* clock = new QuicClock(); // Deleted by scoped ptr of TestConnectionHelper
  QuicRandom* random_generator = QuicRandom::GetInstance();

  TestConnectionHelper* helper = new TestConnectionHelper(task_runner, clock, random_generator); // Deleted by delete_go_quic_client_session()

  QuicPacketWriter* writer = new GoQuicClientPacketWriter(go_udp_conn); // Deleted by ~QuicConnection() because owns_writer is true

  QuicVersionVector supported_versions;
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    supported_versions.push_back(kSupportedQuicVersions[i]);
  }

  // Deleted automatically by scoped ptr of GoQuicClientSession
  QuicConnection* conn = new QuicConnection(
      QuicRandom::GetInstance()->RandUint64(),   // Connection ID
      *server_address,
      helper,
      GoQuicPacketWriterFactory(writer),
      /* owns_writer= */ true,
      /* is_server= */ Perspective::IS_CLIENT,
      /* is_https= */ false,
      supported_versions);

  GoQuicClientSession* session = new GoQuicClientSession(config, conn, helper);  // Deleted by delete_go_quic_client_session()

  // TODO(hodduc) "crypto_config" should be shared as global constant, but there is no clean way to do it now T.T
  // Deleted by ~GoQuicClientSession()
  QuicCryptoClientConfig* crypto_config = new QuicCryptoClientConfig();

  session->InitializeSession(QuicServerId(
        /* host */ std::string(),//server_address->ToStringWithoutPort(),
        /* port */ server_address->port(),
        /* is_https */ false), crypto_config);

  session->CryptoConnect();
  return session;
}

void delete_go_quic_client_session(GoQuicClientSession* go_quic_client_session) {
  QuicConnectionHelperInterface* helper = go_quic_client_session->helper();
  delete go_quic_client_session;
  delete helper;
}

int go_quic_client_encryption_being_established(GoQuicClientSession* session) {
  return (!session->IsEncryptionEstablished() &&
    session->connection()->connected()) ? 1 : 0;
}

int go_quic_client_session_is_connected(GoQuicClientSession* session) {
  return session->connection()->connected() ? 1 : 0;
}

GoQuicReliableClientStream* quic_client_session_create_reliable_quic_stream(GoQuicClientSession* session, void* go_client_stream_) {
  GoQuicReliableClientStream* stream = session->CreateOutgoingDataStream();
  stream->SetGoQuicClientStream(go_client_stream_);
  return stream;
}

int quic_client_session_num_active_requests(GoQuicClientSession* session) {
  return session->num_active_requests();
}

void quic_reliable_client_stream_write_headers(GoQuicReliableClientStream* stream, MapStrStr* header, int is_empty_body) {
  stream->WriteHeaders(*(SpdyHeaderBlock*)header, is_empty_body, nullptr);
}

void quic_reliable_client_stream_write_or_buffer_data(GoQuicReliableClientStream* stream, char* buf, size_t bufsize, int fin) {
  stream->WriteOrBufferData_(StringPiece(buf, bufsize), (fin != 0), nullptr);
}

void go_quic_client_session_process_packet(GoQuicClientSession *session, struct GoIPEndPoint *go_self_address, struct GoIPEndPoint *go_peer_address, char *buffer, size_t length) {
  IPAddressNumber self_ip_addr(go_self_address->ip_buf, go_self_address->ip_buf + go_self_address->ip_length);
  IPEndPoint self_address(self_ip_addr, go_self_address->port);
  IPAddressNumber peer_ip_addr(go_peer_address->ip_buf, go_peer_address->ip_buf + go_peer_address->ip_length);
  IPEndPoint peer_address(peer_ip_addr, go_peer_address->port);

  QuicEncryptedPacket packet(buffer, length, false /* Do not own the buffer, so will not free buffer in the destructor */);

  session->connection()->ProcessUdpPacket(self_address, peer_address, packet);
}

void go_quic_client_session_connection_send_connection_close_packet(GoQuicClientSession* session) {
  session->connection()->SendConnectionClosePacket(QUIC_PEER_GOING_AWAY, "");
}
