#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif
void WriteToUDP_C(void* go_writer, void* peer_ip, size_t peer_ip_sz, uint16_t peer_port, void* buffer, size_t buf_len);
void WriteToUDPClient_C(void* go_writer, void* peer_ip, size_t peer_ip_sz, uint16_t peer_port, void* buffer, size_t buf_len);
void* CreateGoSession_C(void* go_quic_dispatcher, void* quic_server_session);
void* DeleteGoSession_C(void* go_quic_dispatcher, void* go_quic_server_session);
int GetProof_C(void* go_quic_dispatcher, void* server_ip, size_t server_ip_sz, char* hostname, size_t hostname_sz, char* server_config, size_t server_config_sz, int ecdsa_ok, char ***out_certs, int *out_certs_sz, size_t **out_certs_item_sz, char **out_signature, size_t *out_signature_sz);
void* CreateIncomingDynamicStream_C(void* go_quic_server_session, uint32_t id, void* go_quic_spdy_server_stream_go_wrapper);
void UnregisterQuicServerStreamFromSession_C(void* go_stream);
void UnregisterQuicClientStreamFromSession_C(void* go_stream);

void* CreateGoQuicAlarm_C(void* go_quic_alarm_go_wrapper, void* clock, void* go_task_runner);
void GoQuicAlarmSetImpl_C(void* go_quic_alarm, int64_t deadline);
void GoQuicAlarmCancelImpl_C(void* go_quic_alarm);
void GoQuicAlarmDestroy_C(void *go_quic_alarm);

void GoQuicSpdyClientStreamOnStreamHeadersComplete_C(void* go_quic_spdy_client_stream, const char *data, uint32_t data_len);
void GoQuicSpdyClientStreamOnDataAvailable_C(void* go_quic_spdy_client_stream, const char *data, uint32_t data_len, int is_closed);
void GoQuicSpdyClientStreamOnClose_C(void* go_quic_spdy_client_stream);
void GoQuicSpdyServerStreamOnStreamHeadersComplete_C(void* go_quic_spdy_client_stream, const char *data, uint32_t data_len);
void GoQuicSpdyServerStreamOnDataAvailable_C(void* go_quic_spdy_server_stream, const char *data, uint32_t data_len, int is_closed);
void GoQuicSpdyServerStreamOnClose_C(void* go_quic_spdy_server_stream);
#ifdef __cplusplus
}
#endif
