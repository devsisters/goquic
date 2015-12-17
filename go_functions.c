#include "go_functions.h"

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#include "_cgo_export.h"

void WriteToUDP_C(void* go_writer, void* peer_ip, size_t peer_ip_sz, uint16_t peer_port, void* buffer, size_t buf_len) {
    WriteToUDP(go_writer, peer_ip, peer_ip_sz, peer_port, buffer, buf_len);
}

void WriteToUDPClient_C(void* go_writer, void* peer_ip, size_t peer_ip_sz, uint16_t peer_port, void* buffer, size_t buf_len) {
    WriteToUDPClient(go_writer, peer_ip, peer_ip_sz, peer_port, buffer, buf_len);
}

void* CreateGoSession_C(void* go_quic_dispatcher, void* quic_server_session) {
    return CreateGoSession(go_quic_dispatcher, quic_server_session);
}

void* DeleteGoSession_C(void* go_quic_dispatcher, void* go_quic_server_session) {
    DeleteGoSession(go_quic_dispatcher, go_quic_server_session);
}

int GetProof_C(void* go_proof_source, void* server_ip, size_t server_ip_sz, char* hostname, size_t hostname_sz, char* server_config, size_t server_config_sz, int ecdsa_ok, char ***out_certs, int *out_certs_sz, size_t **out_certs_item_sz, char **out_signature, size_t *out_signature_sz) {
    return GetProof(go_proof_source, server_ip, server_ip_sz, hostname, hostname_sz, server_config, server_config_sz, ecdsa_ok, out_certs, out_certs_sz, out_certs_item_sz, out_signature, out_signature_sz);
}

void* CreateIncomingDynamicStream_C(void* go_quic_server_session, uint32_t id, void* go_quic_spdy_server_stream_go_wrapper) {
    return CreateIncomingDynamicStream(go_quic_server_session, id, go_quic_spdy_server_stream_go_wrapper);
}

void UnregisterQuicServerStreamFromSession_C(void* go_stream) {
    UnregisterQuicServerStreamFromSession(go_stream);
}

void UnregisterQuicClientStreamFromSession_C(void* go_stream) {
    UnregisterQuicClientStreamFromSession(go_stream);
}

void* CreateGoQuicAlarm_C(void* go_quic_alarm_go_wrapper, void* clock, void* task_runner) {
    return CreateGoQuicAlarm(go_quic_alarm_go_wrapper, clock, task_runner);
}

void GoQuicAlarmSetImpl_C(void *go_quic_alarm, int64_t deadline) {
    GoQuicAlarmSetImpl(go_quic_alarm, deadline);
}

void GoQuicAlarmCancelImpl_C(void *go_quic_alarm) {
    GoQuicAlarmCancelImpl(go_quic_alarm);
}

void GoQuicAlarmDestroy_C(void *go_quic_alarm) {
    GoQuicAlarmDestroy(go_quic_alarm);
}

void GoQuicSpdyClientStreamOnStreamHeadersComplete_C(void* go_quic_spdy_client_stream, const char *data, uint32_t data_len) {
    GoQuicSpdyClientStreamOnStreamHeadersComplete(go_quic_spdy_client_stream, (void *)data, data_len);
}
void GoQuicSpdyClientStreamOnDataAvailable_C(void* go_quic_spdy_client_stream, const char *data, uint32_t data_len, int is_closed) {
    GoQuicSpdyClientStreamOnDataAvailable(go_quic_spdy_client_stream, (void *)data, data_len, is_closed);
}
void GoQuicSpdyClientStreamOnClose_C(void* go_quic_spdy_client_stream) {
    GoQuicSpdyClientStreamOnClose(go_quic_spdy_client_stream);
}

void GoQuicSpdyServerStreamOnStreamHeadersComplete_C(void* go_quic_spdy_server_stream, const char *data, uint32_t data_len) {
    GoQuicSpdyServerStreamOnStreamHeadersComplete(go_quic_spdy_server_stream, (void *)data, data_len);
}
void GoQuicSpdyServerStreamOnDataAvailable_C(void* go_quic_spdy_server_stream, const char *data, uint32_t data_len, int is_closed) {
    GoQuicSpdyServerStreamOnDataAvailable(go_quic_spdy_server_stream, (void *)data, data_len, is_closed);
}

void GoQuicSpdyServerStreamOnClose_C(void* go_quic_spdy_server_stream) {
    GoQuicSpdyServerStreamOnClose(go_quic_spdy_server_stream);
}

void* NewProofVerifyJob_C(void* go_proof_verifier, const char* hostname, size_t hostname_len, const char* server_config, size_t server_config_len, const char* cert_sct, size_t cert_sct_len, const char* signature, size_t signature_len) {
    return NewProofVerifyJob(go_proof_verifier, (void *)hostname, hostname_len, (void *)server_config, server_config_len, (void *)cert_sct, cert_sct_len, (void *)signature, signature_len);
}

void ProofVerifyJobAddCert_C(void* job, const char* cert, size_t cert_len) {
    ProofVerifyJobAddCert(job, (void *)cert, cert_len);
}

int ProofVerifyJobVerifyProof_C(void* job) {
    return ProofVerifyJobVerifyProof(job);
}
