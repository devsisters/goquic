#include "adaptor_client.h"

#include "go_quic_client_session.h"
#include "go_quic_spdy_client_stream.h"
#include "go_quic_client_packet_writer.h"
#include "go_quic_alarm_factory.h"
#include "go_quic_connection_helper.h"
#include "go_proof_verifier.h"
#include "go_utils.h"

#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_clock.h"
#include "net/quic/core/quic_protocol.h"
#include "net/quic/core/crypto/quic_random.h"
#include "base/strings/string_piece.h"

using namespace net;
using namespace std;
using base::StringPiece;

GoQuicClientSession* create_go_quic_client_session_and_initialize(
    GoPtr go_writer,
    GoPtr task_runner,
    GoPtr go_proof_verifier,
    uint8_t* server_address_ip,
    size_t server_address_len,
    uint16_t server_address_port) {
  IPAddress server_ip_addr(server_address_ip, server_address_len);
  IPEndPoint server_address(server_ip_addr, server_address_port);

  QuicConfig config = QuicConfig();
  QuicClock* clock =
      new QuicClock();  // Deleted by scoped ptr of GoQuicConnectionHelper
  QuicRandom* random_generator = QuicRandom::GetInstance();

  GoQuicConnectionHelper* helper = new GoQuicConnectionHelper(clock, random_generator);  // Deleted by unique_ptr

  GoQuicAlarmFactory* alarm_factory = new GoQuicAlarmFactory(clock, task_runner); // Deleted by unique_ptr

  QuicPacketWriter* writer = new GoQuicClientPacketWriter(
      go_writer);  // Deleted by ~QuicConnection() because owns_writer is true

  QuicVersionVector supported_versions;
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    supported_versions.push_back(kSupportedQuicVersions[i]);
  }

  // Deleted automatically by scoped ptr of GoQuicClientSession
  QuicConnection* conn = new QuicConnection(
      QuicRandom::GetInstance()->RandUint64(),  // Connection ID
      server_address, helper, alarm_factory, writer,
      /* owns_writer= */ true,
      /* is_server= */ Perspective::IS_CLIENT, supported_versions);

  QuicServerId server_id(
      /* host */ std::string(),  // server_address->ToStringWithoutPort(),
      /* port */ server_address.port(), net::PRIVACY_MODE_DISABLED);

  // TODO(hodduc) "crypto_config" should be shared as global constant, but there
  // is no clean way to do it now T.T
  // Deleted by ~GoQuicClientSession()
  std::unique_ptr<GoProofVerifier> proof_verifier(new GoProofVerifier(go_proof_verifier));
  QuicCryptoClientConfig* crypto_config =
      new QuicCryptoClientConfig(std::move(proof_verifier));
  // TODO(hodduc): crypto_config proofverifier?

  GoQuicClientSession* session = new GoQuicClientSession(
      config, conn, server_id, crypto_config, nullptr);  // Deleted by delete_go_quic_client_session()

  session->Initialize();
  session->CryptoConnect();

  return session;
}

void delete_go_quic_client_session(
    GoQuicClientSession* go_quic_client_session) {
  delete go_quic_client_session;
}

int go_quic_client_encryption_being_established(GoQuicClientSession* session) {
  return (!session->IsEncryptionEstablished() &&
          session->connection()->connected())
             ? 1
             : 0;
}

int go_quic_client_session_is_connected(GoQuicClientSession* session) {
  return session->connection()->connected() ? 1 : 0;
}

GoQuicSpdyClientStream* quic_client_session_create_reliable_quic_stream(
    GoQuicClientSession* session,
    GoPtr go_quic_client_stream) {
  GoQuicSpdyClientStream* stream =
      session->CreateOutgoingDynamicStream(kDefaultPriority);
  stream->SetGoQuicClientStream(go_quic_client_stream);
  return stream;
}

int quic_client_session_num_active_requests(GoQuicClientSession* session) {
  return session->num_active_requests();
}

void quic_spdy_client_stream_write_headers(GoQuicSpdyClientStream* stream,
                                           int header_size,
                                           char* header_keys,
                                           int* header_key_len,
                                           char* header_values,
                                           int* header_value_len,
                                           int is_empty_body) {
  SpdyHeaderBlock block;
  CreateSpdyHeaderBlock(block, header_size, header_keys, header_key_len, header_values, header_value_len);
  stream->WriteHeaders(std::move(block), is_empty_body, nullptr);
}

void quic_spdy_client_stream_write_or_buffer_data(
    GoQuicSpdyClientStream* stream,
    char* buf,
    size_t bufsize,
    int fin) {
  stream->WriteOrBufferBody(std::string(buf, bufsize), (fin != 0), nullptr);
}

void go_quic_client_session_process_packet(GoQuicClientSession* session,
                                           uint8_t* self_address_ip,
                                           size_t self_address_len,
                                           uint16_t self_address_port,
                                           uint8_t* peer_address_ip,
                                           size_t peer_address_len,
                                           uint16_t peer_address_port,
                                           char* buffer,
                                           size_t length) {
  IPAddress self_ip_addr(self_address_ip, self_address_len);
  IPEndPoint self_address(self_ip_addr, self_address_port);
  IPAddress peer_ip_addr(peer_address_ip, peer_address_len);
  IPEndPoint peer_address(peer_ip_addr, peer_address_port);

  // TODO(hodduc): what is `socket timestamping`?
  QuicReceivedPacket packet(
      buffer, length, session->connection()->helper()->GetClock()->Now(),
      false /* Do not own the buffer, so will not free buffer in the destructor */);

  session->ProcessUdpPacket(self_address, peer_address, packet);
}

void go_quic_client_session_connection_send_connection_close_packet(
    GoQuicClientSession* session) {
  session->connection()->CloseConnection(
      QUIC_PEER_GOING_AWAY, "Client disconnectiong",
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}
