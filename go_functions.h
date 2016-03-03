#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif
void WriteToUDP_C(int64_t go_writer, void* peer_ip, size_t peer_ip_sz, uint16_t peer_port, void* buffer, size_t buf_len);
void WriteToUDPClient_C(int64_t go_writer, void* peer_ip, size_t peer_ip_sz, uint16_t peer_port, void* buffer, size_t buf_len);
int64_t CreateGoSession_C(int64_t go_quic_dispatcher, void* quic_server_session);
void DeleteGoSession_C(int64_t go_quic_dispatcher, int64_t go_quic_server_session);
int GetProof_C(int64_t go_proof_source, void* server_ip, size_t server_ip_sz, char* hostname, size_t hostname_sz, char* server_config, size_t server_config_sz, int ecdsa_ok, char ***out_certs, int *out_certs_sz, size_t **out_certs_item_sz, char **out_signature, size_t *out_signature_sz);
int64_t CreateIncomingDynamicStream_C(int64_t go_quic_server_session, uint32_t id, void* go_quic_simple_server_stream_go_wrapper);
void UnregisterQuicServerStreamFromSession_C(int64_t go_stream);
void UnregisterQuicClientStreamFromSession_C(int64_t go_stream);

int64_t CreateGoQuicAlarm_C(void* go_quic_alarm_go_wrapper, void* clock, int64_t go_task_runner);
void GoQuicAlarmSetImpl_C(int64_t go_quic_alarm, int64_t deadline);
void GoQuicAlarmCancelImpl_C(int64_t go_quic_alarm);
void GoQuicAlarmDestroy_C(int64_t go_quic_alarm);

void GoQuicSpdyClientStreamOnInitialHeadersComplete_C(int64_t go_quic_spdy_client_stream, const char *data, uint32_t data_len);
void GoQuicSpdyClientStreamOnTrailingHeadersComplete_C(int64_t go_quic_spdy_client_stream, const char *data, uint32_t data_len);
void GoQuicSpdyClientStreamOnDataAvailable_C(int64_t go_quic_spdy_client_stream, const char *data, uint32_t data_len, int is_closed);
void GoQuicSpdyClientStreamOnClose_C(int64_t go_quic_spdy_client_stream);
void GoQuicSimpleServerStreamOnInitialHeadersComplete_C(int64_t go_quic_spdy_client_stream, const char *data, uint32_t data_len);
void GoQuicSimpleServerStreamOnTrailingHeadersComplete_C(int64_t go_quic_spdy_client_stream, const char *data, uint32_t data_len);
void GoQuicSimpleServerStreamOnDataAvailable_C(int64_t go_quic_simple_server_stream, const char *data, uint32_t data_len, int is_closed);
void GoQuicSimpleServerStreamOnClose_C(int64_t go_quic_simple_server_stream);

int64_t NewProofVerifyJob_C(int64_t go_proof_verifier, const char* hostname, size_t hostname_len, const char* server_config, size_t server_config_len, const char* cert_sct, size_t cert_sct_len, const char* signature, size_t signature_len);
void ProofVerifyJobAddCert_C(int64_t job, const char* cert, size_t cert_len);
int ProofVerifyJobVerifyProof_C(int64_t job);

void ReleaseClientWriter_C(int64_t go_client_writer);
void ReleaseServerWriter_C(int64_t go_server_writer);
void ReleaseQuicDispatcher_C(int64_t go_quic_dispatcher);
void ReleaseTaskRunner_C(int64_t go_task_runner);
void ReleaseProofSource_C(int64_t go_proof_source);
void ReleaseProofVerifier_C(int64_t go_proof_verifier);

#ifdef __cplusplus
}
#endif
