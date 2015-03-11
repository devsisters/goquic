#ifndef __ADAPTOR_H__
#define __ADAPTOR_H__
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#include "go_quic_dispatcher.h"
#include "go_quic_spdy_server_stream_go_wrapper.h"
#include "go_quic_alarm_go_wrapper.h"
#include "go_quic_server_packet_writer.h"
#include "base/basictypes.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_protocol.h"
#include "net/base/net_util.h"
#include "net/base/ip_endpoint.h"
using namespace net;

typedef std::map<std::string, std::string> MapStrStr;
extern "C" {
#else
typedef void QuicConnection;
typedef void QuicEncryptedPacket;
typedef void IPAddressNumber;
typedef void IPEndPoint;
typedef void GoQuicDispatcher;
typedef void GoQuicSpdyServerStreamGoWrapper;
typedef void MapStrStr;
typedef void GoQuicAlarmGoWrapper;
typedef void QuicClock;
typedef void GoQuicServerPacketWriter;
#endif
void initialize();
void set_log_level(int level);

/*
void *create_quic_connection(int connection_id, IPEndPoint *ip_endpoint);
int quic_connection_version(QuicConnection *c);
void quic_connection_process_udp_packet(QuicConnection *conn, IPEndPoint *self_address, IPEndPoint *peer_address, QuicEncryptedPacket *packet);
*/

QuicEncryptedPacket *create_quic_encrypted_packet(char *buffer, size_t length);
void delete_quic_encrypted_packet(QuicEncryptedPacket *packet);

IPAddressNumber *create_ip_address_number(unsigned char *ip_buf, size_t length);
void delete_ip_address_number(IPAddressNumber *ip);

IPEndPoint *create_ip_end_point(IPAddressNumber *ip, uint16_t port);
void delete_ip_end_point(IPEndPoint *ip_end_point);
size_t ip_endpoint_ip_address(IPEndPoint *ip_end_point, void *address_buf);
uint16_t ip_endpoint_port(IPEndPoint *ip_end_point);

GoQuicDispatcher *create_quic_dispatcher(void* go_udp_conn, void* go_quic_dispatcher, void* go_task_runner);
void delete_go_quic_dispatcher(GoQuicDispatcher *dispatcher);
void quic_dispatcher_process_packet(GoQuicDispatcher *dispatcher, IPEndPoint *self_address, IPEndPoint *peer_address, QuicEncryptedPacket *packet);

MapStrStr* initialize_map();
void delete_map(MapStrStr* map);
void insert_map(MapStrStr* map, char* key, size_t key_len, char* value, size_t value_len);

void quic_spdy_server_stream_write_headers(GoQuicSpdyServerStreamGoWrapper* wrapper, MapStrStr* header, int is_empty_body);
void quic_spdy_server_stream_write_or_buffer_data(GoQuicSpdyServerStreamGoWrapper* wrapper, char* buf, size_t bufsize, int fin);
void go_quic_alarm_fire(GoQuicAlarmGoWrapper* go_quic_alarm);
int64_t clock_now(QuicClock* clock);
void packet_writer_on_write_complete(GoQuicServerPacketWriter* cb, int rv);
void quic_spdy_server_stream_close_read_side(GoQuicSpdyServerStreamGoWrapper* wrapper);
void test_quic();
#ifdef __cplusplus
}
#endif
#endif  // __ADAPTOR_H__
