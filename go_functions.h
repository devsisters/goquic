#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
void WriteToUDP_C(void* go_udp_conn, void* peer_address, void* buffer, size_t buf_len);
void* CreateGoSession_C(void* go_quic_dispatcher, void* quic_server_session);
void* CreateIncomingDataStream_C(void *go_quic_server_session, uint32_t id);
uint32_t DataStreamProcessorProcessData_C(void* go_data_stream_processor, const char *data, uint32_t data_len);
void DataStreamProcessorOnFinRead_C(void* go_data_stream_processor);
#ifdef __cplusplus
}
#endif
