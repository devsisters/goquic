#include "adaptor.h"

#include "go_quic_dispatcher.h"
#include "go_quic_connection_helper.h"
#include "go_quic_server_packet_writer.h"
#include "go_quic_spdy_server_stream_go_wrapper.h"
#include "go_quic_alarm_go_wrapper.h"
#include "go_proof_source.h"
#include "go_ephemeral_key_source.h"

#include "net/quic/quic_connection.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_time.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/crypto/quic_random.h"
#include "net/base/net_util.h"
#include "net/base/ip_endpoint.h"
#include "base/strings/string_piece.h"
#include "base/basictypes.h"

#include "base/command_line.h"
#include "base/at_exit.h"
#include "base/logging.h"

#include <iostream>
#include <vector>

#define EXPECT_TRUE(x) { if (!(x)) printf("ERROR"); }

using namespace net;
using namespace std;
using base::StringPiece;



static base::AtExitManager *exit_manager;
void initialize() {
  int argc = 1;
  const char *argv[] = {"test", nullptr};
  base::CommandLine::Init(argc, argv);
  exit_manager = new base::AtExitManager;   // Deleted at the end
}

void set_log_level(int level) {
  logging::SetMinLogLevel(level);
}

GoQuicDispatcher *create_quic_dispatcher(void* go_udp_conn, void* go_quic_dispatcher, void* go_task_runner) {
  QuicConfig config;

  // TODO(serialx, hodduc): What is "secret"?
  // TODO(hodduc) "crypto_config" should be shared as global constant, but there is no clean way to do it now T.T
  // Deleted by ~GoQuicDispatcher()
  QuicCryptoServerConfig* crypto_config = new QuicCryptoServerConfig("secret", QuicRandom::GetInstance());
  QuicClock* clock = new QuicClock(); // Deleted by scoped ptr of TestConnectionHelper
  QuicRandom* random_generator = QuicRandom::GetInstance();
  net::EphemeralKeySource *keySource = new GoEphemeralKeySource();
  crypto_config->SetEphemeralKeySource(keySource);

  TestConnectionHelper *helper = new TestConnectionHelper(go_task_runner, clock, random_generator); // Deleted by delete_go_quic_dispatcher()
  QuicVersionVector versions(net::QuicSupportedVersions());

  /* Initialize Configs ------------------------------------------------*/

  // If an initial flow control window has not explicitly been set, then use a
  // sensible value for a server: 1 MB for session, 64 KB for each stream.
  const uint32 kInitialSessionFlowControlWindow = 1 * 1024 * 1024;  // 1 MB
  const uint32 kInitialStreamFlowControlWindow = 64 * 1024;         // 64 KB
  if (config.GetInitialStreamFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config.SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindow);
  }
  if (config.GetInitialSessionFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config.SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindow);
  }

  GoProofSource *proofSource = new GoProofSource(go_quic_dispatcher);  // Deleted by scoped ptr of QuicCryptoServerConfig
  crypto_config->SetProofSource(proofSource);

  scoped_ptr<CryptoHandshakeMessage> scfg(
      crypto_config->AddDefaultConfig(
          helper->GetRandomGenerator(), helper->GetClock(),
          QuicCryptoServerConfig::ConfigOptions()));
  /* Initialize Configs Ends ----------------------------------------*/

  // Deleted by delete_go_quic_dispatcher()
  GoQuicDispatcher* dispatcher = new GoQuicDispatcher(config,
      *crypto_config,
      versions,
      new GoQuicDispatcher::DefaultPacketWriterFactory(),  // Delete by scoped ptr of GoQuicDispatcher
      helper,
      go_quic_dispatcher);

  GoQuicServerPacketWriter* writer = new GoQuicServerPacketWriter(go_udp_conn, dispatcher); // Deleted by scoped ptr of GoQuicDispatcher

  dispatcher->Initialize(writer);

  return dispatcher;
}

void delete_go_quic_dispatcher(GoQuicDispatcher *dispatcher) {
  QuicConnectionHelperInterface* helper = dispatcher->helper();
  delete dispatcher;
  delete helper;
}

void quic_dispatcher_process_packet(GoQuicDispatcher *dispatcher, struct GoIPEndPoint *go_self_address, struct GoIPEndPoint *go_peer_address, char *buffer, size_t length) {
  IPAddressNumber *self_ip_addr, *peer_ip_addr;
  self_ip_addr = create_ip_address_number(go_self_address->ip_buf, go_self_address->ip_length);
  IPEndPoint self_address(*self_ip_addr, go_self_address->port);
  delete self_ip_addr;

  peer_ip_addr = create_ip_address_number(go_peer_address->ip_buf, go_peer_address->ip_length);
  IPEndPoint peer_address(*peer_ip_addr, go_peer_address->port);
  delete peer_ip_addr;

  QuicEncryptedPacket packet(buffer, length, false /* Do not own the buffer, so will not free buffer in the destructor */);

  dispatcher->ProcessPacket(self_address, peer_address, packet);
}

QuicEncryptedPacket *create_quic_encrypted_packet(char *buffer, size_t length) {
  return new QuicEncryptedPacket(buffer, length, false /* Do not own the buffer, so will not free buffer in the destructor */);  // Deleted by delete_quic_encrypted_packet()
}

void delete_quic_encrypted_packet(QuicEncryptedPacket *packet) {
  delete packet;
}

IPAddressNumber *create_ip_address_number(unsigned char *ip_buf, size_t length) {
  IPAddressNumber *ip = new IPAddressNumber; // Deleted by delete_ip_address_number()
  for (size_t i = 0; i < length; i++) {
    ip->push_back(ip_buf[i]);
  }
  return ip;
}

void delete_ip_address_number(IPAddressNumber *ip) {
  delete ip;
}

size_t ip_address_number_ip_address(IPAddressNumber *ip, void *address_buf) {
  const size_t size = ip->size();
  for (size_t i = 0; i < size; i++) {
    // XXX(serialx): Performance and safety issues here. Ensure address_buf is large enough for ipv6
    ((char *)address_buf)[i] = ip->at(i);
  }
  return size;
}

IPEndPoint *create_ip_end_point(IPAddressNumber *ip, uint16_t port) {
  return new IPEndPoint(*ip, port); // Deleted by delete_ip_end_point()
}

size_t ip_endpoint_ip_address(IPEndPoint *ip_end_point, void *address_buf) {
  const IPAddressNumber &ip = ip_end_point->address();
  const size_t size = ip.size();
  for (size_t i = 0; i < size; i++) {
    // XXX(serialx): Performance and safety issues here. Ensure address_buf is large enough for ipv6
    ((char *)address_buf)[i] = ip[i];
  }
  return size;
}

uint16_t ip_endpoint_port(IPEndPoint *ip_end_point) {
  return ip_end_point->port();
}

void delete_ip_end_point(IPEndPoint *ip_end_point) {
  delete ip_end_point;
}

// Utility wrappers for C++ std::map
MapStrStr* initialize_map() {
  return new MapStrStr; // Delete by delete_map
}

void delete_map(MapStrStr* map) {
  delete map;
}

void insert_map(MapStrStr* map, char* key, size_t key_len, char* value, size_t value_len) {
  map->insert(
      std::pair<std::string, std::string>(std::string(key, key_len), std::string(value, value_len)));
}

void quic_spdy_server_stream_write_headers(GoQuicSpdyServerStreamGoWrapper* wrapper, MapStrStr* header, int is_empty_body) {
  wrapper->WriteHeaders(*(SpdyHeaderBlock*)header, is_empty_body, nullptr);
}

void quic_spdy_server_stream_write_or_buffer_data(GoQuicSpdyServerStreamGoWrapper* wrapper, char* buf, size_t bufsize, int fin) {
  wrapper->WriteOrBufferData_(StringPiece(buf, bufsize), (fin != 0), nullptr);
}

void go_quic_alarm_fire(GoQuicAlarmGoWrapper* go_quic_alarm) {
  go_quic_alarm->Fire_();
}

int64_t clock_now(QuicClock* quic_clock) {
  return quic_clock->Now().Subtract(QuicTime::Zero()).ToMicroseconds();
}

void packet_writer_on_write_complete(GoQuicServerPacketWriter* cb, int rv) {
  cb->OnWriteComplete(rv);
}

void quic_spdy_server_stream_close_read_side(GoQuicSpdyServerStreamGoWrapper* wrapper) {
  wrapper->CloseReadSide_();
}
