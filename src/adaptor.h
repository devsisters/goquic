#ifndef __ADAPTOR_H__
#define __ADAPTOR_H__
#include <stddef.h>
#include <stdint.h>

#include "go_structs.h"

#ifdef __cplusplus
#include "go_quic_simple_dispatcher.h"
#include "go_quic_simple_server_stream.h"
#include "go_quic_alarm_go_wrapper.h"
#include "go_quic_server_packet_writer.h"
#include "proof_source_goquic.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_protocol.h"
#include "net/base/ip_endpoint.h"
#include "net/spdy/spdy_header_block.h"

using namespace net;

extern "C" {
#else
typedef void QuicConnection;
typedef void GoQuicSimpleDispatcher;
typedef void GoQuicSimpleServerStream;
typedef void SpdyHeaderBlock;
typedef void GoQuicAlarmGoWrapper;
typedef void QuicClock;
typedef void GoQuicServerPacketWriter;
typedef void QuicCryptoServerConfig;
typedef void ProofSourceGoquic;
typedef void QuicServerSessionBase;
#endif

void initialize();
void set_log_level(int level);

struct GoQuicServerConfig* generate_goquic_crypto_config();
struct GoQuicServerConfig* create_goquic_crypto_config(char* server_config, size_t server_config_len, int key_size);
void goquic_crypto_config_set_key(struct GoQuicServerConfig* gocfg, int index, uint32_t tag, char* key, size_t key_len);
void delete_goquic_crypto_config(struct GoQuicServerConfig* gocfg);

QuicCryptoServerConfig* init_crypto_config(
    struct GoQuicServerConfig* go_config,
    ProofSourceGoquic* proof_source,
    char* source_address_token_secret,
    size_t source_address_token_secret_len);

void delete_crypto_config(QuicCryptoServerConfig* config);

GoQuicSimpleDispatcher* create_quic_dispatcher(GoPtr go_writer_,
                                         GoPtr go_quic_dispatcher,
                                         GoPtr go_task_runner,
                                         QuicCryptoServerConfig* crypto_config);
void delete_go_quic_dispatcher(GoQuicSimpleDispatcher* dispatcher);
void quic_dispatcher_process_packet(GoQuicSimpleDispatcher* dispatcher,
                                    uint8_t* self_address_ip,
                                    size_t self_address_len,
                                    uint16_t self_address_port,
                                    uint8_t* peer_address_ip,
                                    size_t peer_address_len,
                                    uint16_t peer_address_port,
                                    char* buffer,
                                    size_t length);

SpdyHeaderBlock* initialize_header_block();
void delete_header_block(SpdyHeaderBlock* map);
void insert_header_block(SpdyHeaderBlock* map,
                         char* key,
                         size_t key_len,
                         char* value,
                         size_t value_len);

void quic_simple_server_stream_write_headers(GoQuicSimpleServerStream* wrapper,
                                             int header_size,
                                             char* header_keys,
                                             int* header_key_len,
                                             char* header_values,
                                             int* header_value_len,
                                             int is_empty_body);
void quic_simple_server_stream_write_or_buffer_data(GoQuicSimpleServerStream* wrapper, char* buf, size_t bufsize, int fin);
void quic_simple_server_stream_write_trailers(GoQuicSimpleServerStream* wrapper,
                                              int header_size,
                                              char* header_keys,
                                              int* header_key_len,
                                              char* header_values,
                                              int* header_value_len);

void go_quic_alarm_fire(GoQuicAlarmGoWrapper* go_quic_alarm);
int64_t clock_now(QuicClock* clock);
void packet_writer_on_write_complete(GoQuicServerPacketWriter* cb, int rv);
struct ConnStat quic_server_session_connection_stat(QuicServerSessionBase* sess);

ProofSourceGoquic* init_proof_source_goquic(GoPtr go_proof_source);
void proof_source_goquic_add_cert(ProofSourceGoquic* proof_source, char* cert_c, size_t cert_sz);
void proof_source_goquic_build_cert_chain(ProofSourceGoquic* proof_source);

#ifdef __cplusplus
}
#endif
#endif  // __ADAPTOR_H__
