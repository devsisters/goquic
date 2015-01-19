#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#include "go_quic_dispatcher.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_protocol.h"
#include "net/base/net_util.h"
#include "net/base/ip_endpoint.h"
using namespace net;
extern "C" {
#else
typedef void QuicConnection;
typedef void QuicEncryptedPacket;
typedef void IPAddressNumber;
typedef void IPEndPoint;
typedef void GoQuicDispatcher;
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

GoQuicDispatcher *create_quic_dispatcher(void *go_udp_conn);
void quic_dispatcher_process_packet(GoQuicDispatcher *dispatcher, IPEndPoint *self_address, IPEndPoint *peer_address, QuicEncryptedPacket *packet);

void test_quic();
#ifdef __cplusplus
}
#endif
