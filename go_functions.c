#include "go_functions.h"

#include <stddef.h>

#include "_cgo_export.h"

void WriteToUDP_C(void* go_udp_conn, void* peer_address, void* buffer, size_t buf_len) {

    WriteToUDP(go_udp_conn, peer_address, buffer, buf_len);
}
