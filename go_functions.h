#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif
void WriteToUDP_C(void* go_udp_conn, void* peer_address, void* buffer, size_t buf_len, void* quic_server_packet_writer, void* go_task_runner);
void WriteToUDPSync_C(void* go_udp_conn, void* peer_address, void* buffer, size_t buf_len, void* quic_server_packet_writer, void* go_task_runner);
void* CreateGoSession_C(void* go_quic_dispatcher, void* quic_server_session);
void* GetProof_C(void* go_quic_dispatcher, void* server_ip, char* hostname, size_t hostname_sz, char* server_config, size_t server_config_sz, int ecdsa_ok, char ***out_certs, int *out_certs_sz, size_t **out_certs_item_sz, char **out_signature, size_t *out_signature_sz);
void* CreateIncomingDataStream_C(void* go_quic_server_session, uint32_t id, void* go_quic_spdy_server_stream_go_wrapper);
uint32_t DataStreamProcessorProcessData_C(void* go_data_stream_processor, const char *data, uint32_t data_len);
void DataStreamProcessorOnFinRead_C(void* go_data_stream_processor);

void* CreateGoQuicAlarm_C(void* go_quic_alarm_go_wrapper, void* clock, void* go_task_runner);
void GoQuicAlarmSetImpl_C(void* go_quic_alarm, int64_t deadline, int64_t now);
void GoQuicAlarmCancelImpl_C(void* go_quic_alarm, int64_t now);
#ifdef __cplusplus
}
#endif
