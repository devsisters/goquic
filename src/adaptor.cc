#include "adaptor.h"

#include "go_quic_simple_dispatcher.h"
#include "go_quic_connection_helper.h"
#include "go_quic_server_packet_writer.h"
#include "go_quic_simple_server_stream.h"
#include "go_quic_alarm_go_wrapper.h"
#include "go_quic_alarm_factory.h"
#include "go_quic_simple_server_session_helper.h"
#include "go_utils.h"
#include "proof_source_goquic.h"
#include "go_ephemeral_key_source.h"

#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_clock.h"
#include "net/quic/core/quic_time.h"
#include "net/quic/core/quic_protocol.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/crypto/crypto_server_config_protobuf.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "base/strings/string_piece.h"

#include "base/command_line.h"
#include "base/at_exit.h"
#include "base/logging.h"

#include <iostream>
#include <vector>
#include <stddef.h>

#define EXPECT_TRUE(x) \
  {                    \
    if (!(x))          \
      printf("ERROR"); \
  }

using namespace net;
using namespace std;

static base::AtExitManager* exit_manager;
void initialize() {
  int argc = 1;
  const char* argv[] = {"test", nullptr};
  base::CommandLine::Init(argc, argv);
  exit_manager = new base::AtExitManager;  // Deleted at the end
}

void set_log_level(int level) {
  logging::SetMinLogLevel(level);
}

// crypto config export/import for synchronizing servers (dispatchers)
// to allow 0-rtt connection establishment
struct GoQuicServerConfig* generate_goquic_crypto_config() {
  QuicClock clock;
  QuicRandom* random_generator = QuicRandom::GetInstance();

  std::unique_ptr<QuicServerConfigProtobuf> scfg(
    net::QuicCryptoServerConfig::GenerateConfig(
      random_generator, &clock, QuicCryptoServerConfig::ConfigOptions()));

  GoQuicServerConfig* gocfg = new GoQuicServerConfig;

  string::size_type server_config_len = scfg->config().size();
  gocfg->Server_config_len = server_config_len;
  gocfg->Server_config = new char[server_config_len];
  memcpy(gocfg->Server_config, scfg->config().data(), server_config_len);

  size_t key_size = scfg->key_size();
  gocfg->Num_of_keys = key_size;
  gocfg->Private_keys = new char*[key_size];
  gocfg->Private_keys_len = new int[key_size];
  gocfg->Private_keys_tag = new uint32_t[key_size];

  for(int i = 0; i < key_size; i++) {
    auto key = scfg->key(i);
    gocfg->Private_keys_tag[i] = uint32_t(key.tag());
    string::size_type private_key_len = key.private_key().size();
    gocfg->Private_keys_len[i] = private_key_len;
    gocfg->Private_keys[i] = new char[private_key_len];
    memcpy(gocfg->Private_keys[i], key.private_key().data(), private_key_len);
  }

  return gocfg;
}

struct GoQuicServerConfig* create_goquic_crypto_config(char* server_config, size_t server_config_len, int key_size) {
  GoQuicServerConfig* gocfg = new GoQuicServerConfig;
  gocfg->Server_config_len = server_config_len;
  gocfg->Server_config = new char[server_config_len];
  memcpy(gocfg->Server_config, server_config, server_config_len);

  gocfg->Num_of_keys = key_size;
  gocfg->Private_keys = new char*[key_size];
  gocfg->Private_keys_len = new int[key_size];
  gocfg->Private_keys_tag = new uint32_t[key_size];
  return gocfg;
}

void goquic_crypto_config_set_key(GoQuicServerConfig* gocfg, int index, uint32_t tag, char* key, size_t key_len) {
  if (index >= gocfg->Num_of_keys) return;

  gocfg->Private_keys_tag[index] = tag;
  gocfg->Private_keys_len[index] = key_len;
  gocfg->Private_keys[index] = new char[key_len];
  memcpy(gocfg->Private_keys[index], key, key_len);
}

void delete_goquic_crypto_config(GoQuicServerConfig* gocfg) {
  delete gocfg->Server_config;
  delete gocfg->Private_keys_len;
  delete gocfg->Private_keys_tag;

  for(int i = 0; i < gocfg->Num_of_keys; i++) {
    delete gocfg->Private_keys[i];
  }
  delete gocfg->Private_keys;

  delete gocfg;
}

static QuicServerConfigProtobuf* parse_goquic_crypto_config(GoQuicServerConfig* go_config) {
  QuicServerConfigProtobuf* config = new QuicServerConfigProtobuf;
  config->set_config(string(go_config->Server_config, go_config->Server_config_len));
  for(int i = 0; i < go_config->Num_of_keys; i++) {
    auto key = config->add_key();
    key->set_tag(go_config->Private_keys_tag[i]);
    key->set_private_key(string(go_config->Private_keys[i], go_config->Private_keys_len[i]));
  }
  return config;
}

// Takes ownership of proof_source
QuicCryptoServerConfig* init_crypto_config(
    GoQuicServerConfig* go_config,
    ProofSourceGoquic* proof_source,
    char* source_address_token_secret,
    size_t source_address_token_secret_len) {

  std::unique_ptr<ProofSourceGoquic> proof_source_ptr(proof_source);
  std::unique_ptr<QuicServerConfigProtobuf> config(
      parse_goquic_crypto_config(go_config));

  auto secret = string(source_address_token_secret, source_address_token_secret_len);
  QuicCryptoServerConfig* crypto_config = new QuicCryptoServerConfig(
      secret, QuicRandom::GetInstance(), std::move(proof_source_ptr));

  crypto_config->set_strike_register_no_startup_period();
  net::EphemeralKeySource* keySource = new GoEphemeralKeySource();
  crypto_config->SetEphemeralKeySource(keySource);
  crypto_config->set_replay_protection(false);  // TODO(hodduc): Create strike-register client and turn on replay protection again

  QuicClock* clock = new QuicClock();  // XXX: Not deleted.

  std::unique_ptr<CryptoHandshakeMessage> scfg(
      crypto_config->AddConfig(config.get(), clock->WallNow()));

  return crypto_config;
}

void delete_crypto_config(QuicCryptoServerConfig* crypto_config) {
  delete crypto_config;
}

GoQuicSimpleDispatcher* create_quic_dispatcher(
    GoPtr go_writer,
    GoPtr go_quic_dispatcher,
    GoPtr go_task_runner,
    QuicCryptoServerConfig* crypto_config) {
  QuicConfig* config = new QuicConfig();
  // Deleted by ~GoQuicDispatcher()
  QuicClock* clock =
      new QuicClock();  // Deleted by scoped ptr of GoQuicConnectionHelper
  QuicRandom* random_generator = QuicRandom::GetInstance();

  std::unique_ptr<QuicConnectionHelperInterface> helper(new GoQuicConnectionHelper(clock, random_generator));
  std::unique_ptr<QuicAlarmFactory> alarm_factory(new GoQuicAlarmFactory(clock, go_task_runner));
  std::unique_ptr<QuicCryptoServerStream::Helper> session_helper(new GoQuicSimpleServerSessionHelper(QuicRandom::GetInstance()));
  // XXX: quic_server uses QuicSimpleCryptoServerStreamHelper, 
  // while quic_simple_server uses QuicSimpleServerSessionHelper.
  // Pick one and remove the other later

  QuicVersionManager* version_manager = new QuicVersionManager(net::AllSupportedVersions());

  /* Initialize Configs ------------------------------------------------*/

  // If an initial flow control window has not explicitly been set, then use a
  // sensible value for a server: 1 MB for session, 64 KB for each stream.
  const uint32_t kInitialSessionFlowControlWindow = 1 * 1024 * 1024;  // 1 MB
  const uint32_t kInitialStreamFlowControlWindow = 64 * 1024;         // 64 KB
  if (config->GetInitialStreamFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config->SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindow);
  }
  if (config->GetInitialSessionFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config->SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindow);
  }
  /* Initialize Configs Ends ----------------------------------------*/

  // Deleted by delete_go_quic_dispatcher()
  GoQuicSimpleDispatcher* dispatcher =
      new GoQuicSimpleDispatcher(*config, crypto_config, version_manager,
          std::move(helper), std::move(session_helper), std::move(alarm_factory), go_quic_dispatcher);

  GoQuicServerPacketWriter* writer = new GoQuicServerPacketWriter(
      go_writer, dispatcher);  // Deleted by scoped ptr of GoQuicDispatcher

  dispatcher->InitializeWithWriter(writer);

  return dispatcher;
}

void delete_go_quic_dispatcher(GoQuicSimpleDispatcher* dispatcher) {
  delete dispatcher;
}

void quic_dispatcher_process_packet(GoQuicSimpleDispatcher* dispatcher,
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

  QuicReceivedPacket packet(
      buffer, length, dispatcher->helper()->GetClock()->Now(),
      false /* Do not own the buffer, so will not free buffer in the destructor */);

  dispatcher->ProcessPacket(self_address, peer_address, packet);
}

SpdyHeaderBlock* initialize_header_block() {
  return new SpdyHeaderBlock;  // Delete by delete_header_block
}

void delete_header_block(SpdyHeaderBlock* block) {
  delete block;
}

void insert_header_block(SpdyHeaderBlock* block,
                         char* key,
                         size_t key_len,
                         char* value,
                         size_t value_len) {
  (*block)[base::StringPiece(std::string(key, key_len))] =
      base::StringPiece(std::string(value, value_len));
}

void quic_simple_server_stream_write_headers(GoQuicSimpleServerStream* wrapper,
                                             int header_size,
                                             char* header_keys,
                                             int* header_key_len,
                                             char* header_values,
                                             int* header_value_len,
                                             int is_empty_body) {
  SpdyHeaderBlock block;
  CreateSpdyHeaderBlock(block, header_size, header_keys, header_key_len, header_values, header_value_len);
  wrapper->WriteHeaders(std::move(block), is_empty_body, nullptr);
}

void quic_simple_server_stream_write_or_buffer_data(
    GoQuicSimpleServerStream* wrapper,
    char* buf,
    size_t bufsize,
    int fin) {
  wrapper->WriteOrBufferBody(std::string(buf, bufsize), (fin != 0), nullptr);
}

void quic_simple_server_stream_write_trailers(GoQuicSimpleServerStream* wrapper,
                                              int header_size,
                                              char* header_keys,
                                              int* header_key_len,
                                              char* header_values,
                                              int* header_value_len) {
  SpdyHeaderBlock block;
  CreateSpdyHeaderBlock(block, header_size, header_keys, header_key_len, header_values, header_value_len);
  wrapper->WriteTrailers(std::move(block), nullptr);
}

void go_quic_alarm_fire(GoQuicAlarmGoWrapper* go_quic_alarm) {
  go_quic_alarm->Fire_();
}

int64_t clock_now(QuicClock* quic_clock) {
  return (quic_clock->Now() - QuicTime::Zero()).ToMicroseconds();
}

void packet_writer_on_write_complete(GoQuicServerPacketWriter* cb, int rv) {
  cb->OnWriteComplete(rv);
}

struct ConnStat quic_server_session_connection_stat(QuicServerSessionBase* sess) {
  QuicConnection* conn = sess->connection();
  QuicConnectionStats stats = conn->GetStats();

  struct ConnStat stat = {(uint64_t)(conn->connection_id()),

                          stats.bytes_sent,
                          stats.packets_sent,
                          stats.stream_bytes_sent,
                          stats.packets_discarded,

                          stats.bytes_received,
                          stats.packets_received,
                          stats.packets_processed,
                          stats.stream_bytes_received,

                          stats.bytes_retransmitted,
                          stats.packets_retransmitted,

                          stats.bytes_spuriously_retransmitted,
                          stats.packets_spuriously_retransmitted,
                          stats.packets_lost,

                          stats.slowstart_packets_sent,
                          stats.slowstart_packets_lost,

                          stats.packets_dropped,
                          stats.crypto_retransmit_count,
                          stats.loss_timeout_count,
                          stats.tlp_count,
                          stats.rto_count,

                          stats.min_rtt_us,
                          stats.srtt_us,
                          stats.max_packet_size,
                          stats.max_received_packet_size,

                          stats.estimated_bandwidth.ToBitsPerSecond(),

                          stats.packets_reordered,
                          stats.max_sequence_reordering,
                          stats.max_time_reordering_us,
                          stats.tcp_loss_events};

  return stat;
}

ProofSourceGoquic* init_proof_source_goquic(GoPtr go_proof_source) {
  return new ProofSourceGoquic(go_proof_source);
}

void proof_source_goquic_add_cert(ProofSourceGoquic* proof_source, char* cert_c, size_t cert_sz) {
  proof_source->AddCert(cert_c, cert_sz);
}

void proof_source_goquic_build_cert_chain(ProofSourceGoquic* proof_source) {
  proof_source->BuildCertChain();
}
