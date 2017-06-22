#ifndef __ADAPTOR_CLIENT_H__
#define __ADAPTOR_CLIENT_H__
#include <stddef.h>
#include <stdint.h>

#include "go_structs.h"

#ifdef __cplusplus
#include "go_quic_client_session.h"
#include "go_quic_spdy_client_stream.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/core/quic_protocol.h"
using namespace net;

extern "C" {
#else
typedef void IPEndPoint;
typedef void GoQuicClientSession;
typedef void GoQuicSpdyClientStream;
#endif

GoQuicClientSession* create_go_quic_client_session_and_initialize(
    GoPtr go_writer,
    GoPtr task_runner,
    GoPtr go_proof_verifier,
    uint8_t* server_address_ip,
    size_t server_address_len,
    uint16_t server_address_port);
void delete_go_quic_client_session(GoQuicClientSession* go_quic_client_session);
int go_quic_client_encryption_being_established(GoQuicClientSession* session);
int go_quic_client_session_is_connected(GoQuicClientSession* session);
GoQuicSpdyClientStream* quic_client_session_create_reliable_quic_stream(
    GoQuicClientSession* session,
    GoPtr go_quic_client_stream);
int quic_client_session_num_active_requests(GoQuicClientSession* session);
void quic_spdy_client_stream_write_headers(GoQuicSpdyClientStream* stream,
                                           int header_size,
                                           char* header_keys,
                                           int* header_key_len,
                                           char* header_values,
                                           int* header_value_len,
                                           int is_empty_body);
void quic_spdy_client_stream_write_or_buffer_data(
    GoQuicSpdyClientStream* stream,
    char* buf,
    size_t bufsize,
    int fin);
void go_quic_client_session_process_packet(GoQuicClientSession* session,
                                           uint8_t* self_address_ip,
                                           size_t self_address_len,
                                           uint16_t self_address_port,
                                           uint8_t* peer_address_ip,
                                           size_t peer_address_len,
                                           uint16_t peer_address_port,
                                           char* buffer,
                                           size_t length);
void go_quic_client_session_connection_send_connection_close_packet(
    GoQuicClientSession* session);
#ifdef __cplusplus
}
#endif
#endif  // __ADAPTOR_CLIENT_H__
