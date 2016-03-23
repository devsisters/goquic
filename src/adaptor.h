#ifndef __ADAPTOR_H__
#define __ADAPTOR_H__
#include <stddef.h>
#include <stdint.h>

#include "go_structs.h"

#ifdef __cplusplus
#include "go_quic_dispatcher.h"
#include "go_quic_simple_server_stream.h"
#include "go_quic_alarm_go_wrapper.h"
#include "go_quic_server_packet_writer.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_protocol.h"
#include "net/base/ip_endpoint.h"
#include "net/spdy/spdy_header_block.h"

using namespace net;

extern "C" {
#else
typedef void QuicConnection;
typedef void QuicEncryptedPacket;
typedef void GoQuicDispatcher;
typedef void GoQuicSimpleServerStream;
typedef void GoQuicServerSessionBase;
typedef void SpdyHeaderBlock;
typedef void GoQuicAlarmGoWrapper;
typedef void QuicClock;
typedef void GoQuicServerPacketWriter;
typedef void QuicCryptoServerConfig;
#endif

void initialize();
void set_log_level(int level);

GoQuicDispatcher* create_quic_dispatcher(GoPtr go_writer_,
                                         GoPtr go_quic_dispatcher,
                                         GoPtr go_task_runner,
                                         QuicCryptoServerConfig* crypto_config);
QuicCryptoServerConfig* init_crypto_config(GoPtr go_proof_source);
void delete_go_quic_dispatcher(GoQuicDispatcher* dispatcher);
void quic_dispatcher_process_packet(GoQuicDispatcher* dispatcher,
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
                                             SpdyHeaderBlock* header,
                                             int is_empty_body);
void quic_simple_server_stream_write_or_buffer_data(
    GoQuicSimpleServerStream* wrapper,
    char* buf,
    size_t bufsize,
    int fin);
void go_quic_alarm_fire(GoQuicAlarmGoWrapper* go_quic_alarm);
int64_t clock_now(QuicClock* clock);
void packet_writer_on_write_complete(GoQuicServerPacketWriter* cb, int rv);
struct ConnStat quic_server_session_connection_stat(GoQuicServerSessionBase* sess);
#ifdef __cplusplus
}
#endif
#endif  // __ADAPTOR_H__
