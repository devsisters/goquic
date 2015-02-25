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
  QuicConfig* config = new QuicConfig();
  QuicClock* clock = new QuicClock();
  QuicRandom* random_generator = QuicRandom::GetInstance();

  TestConnectionHelper* helper = new TestConnectionHelper(task_runner, clock, random_generator);

  QuicPacketWriter* writer = new GoQuicClientPacketWriter(go_udp_conn, task_runner);

  QuicVersionVector supported_versions;
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    supported_versions.push_back(kSupportedQuicVersions[i]);
  }

  GoQuicClientSession* session = new GoQuicClientSession(
      *config,
      new QuicConnection(
        QuicRandom::GetInstance()->RandUint64(),   // Connection ID
        *server_address,
        helper,
        GoQuicPacketWriterFactory(writer),
        /* owns_writer= */ false,
        /* is_server= */ false,
        /* is_https= */ false,
        supported_versions));

  session->InitializeSession(QuicServerId(
        /* host */ std::string(),//server_address->ToStringWithoutPort(),
        /* port */ server_address->port(),
        /* is_https */ false), new QuicCryptoClientConfig());
  // TODO(hodduc) crypto config set
  // TODO(hodduc) cryptostreamfactory needed?

  session->CryptoConnect();
  return session;
}

int go_quic_client_encryption_being_established(GoQuicClientSession* session) {
  return (!session->IsEncryptionEstablished() &&
    session->connection()->connected()) ? 1 : 0;
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

void go_quic_client_session_process_packet(GoQuicClientSession *session, IPEndPoint *self_address, IPEndPoint *peer_address, QuicEncryptedPacket *packet) {
  session->connection()->ProcessUdpPacket(*self_address, *peer_address, *packet);
}
