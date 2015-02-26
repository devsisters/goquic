#ifndef __ADAPTOR_CLIENT_H__
#define __ADAPTOR_CLIENT_H__
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#include "go_quic_client_session.h"
#include "go_quic_reliable_client_stream.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/quic_protocol.h"
using namespace net;

typedef std::map<std::string, std::string> MapStrStr;
extern "C" {
#else
typedef void IPEndPoint;
typedef void GoQuicClientSession;
typedef void GoQuicReliableClientStream;
typedef void MapStrStr;
typedef void QuicEncryptedPacket;
#endif
GoQuicClientSession* create_go_quic_client_session_and_initialize(void* go_udp_conn, void* task_runner, IPEndPoint* server_address);
void delete_go_quic_client_session(GoQuicClientSession* go_quic_client_session);
int go_quic_client_encryption_being_established(GoQuicClientSession* session);
int go_quic_client_session_is_connected(GoQuicClientSession* session);
GoQuicReliableClientStream* quic_client_session_create_reliable_quic_stream(GoQuicClientSession* session, void* go_quic_client_stream);
int quic_client_session_num_active_requests(GoQuicClientSession* session);
void quic_reliable_client_stream_write_headers(GoQuicReliableClientStream* stream, MapStrStr* header, int is_empty_body);
void quic_reliable_client_stream_write_or_buffer_data(GoQuicReliableClientStream* stream, char* buf, size_t bufsize, int fin);
void go_quic_client_session_process_packet(GoQuicClientSession *session, IPEndPoint *self_address, IPEndPoint *peer_address, QuicEncryptedPacket *packet);
void go_quic_client_session_connection_send_connection_close_packet(GoQuicClientSession* session);
#ifdef __cplusplus
}
#endif
#endif  // __ADAPTOR_CLIENT_H__
