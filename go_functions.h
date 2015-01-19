#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
void WriteToUDP_C(void* go_udp_conn, void* peer_address, void* buffer, size_t buf_len);
#ifdef __cplusplus
}
#endif
