#include "go_functions.h"

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#include "_cgo_export.h"

void WriteToUDP_C(int64_t go_writer, void* peer_ip, size_t peer_ip_sz, uint16_t peer_port, void* buffer, size_t buf_len) {
    WriteToUDP(go_writer, peer_ip, peer_ip_sz, peer_port, buffer, buf_len);
}

void WriteToUDPClient_C(int64_t go_writer, void* peer_ip, size_t peer_ip_sz, uint16_t peer_port, void* buffer, size_t buf_len) {
    WriteToUDPClient(go_writer, peer_ip, peer_ip_sz, peer_port, buffer, buf_len);
}

int64_t CreateGoSession_C(int64_t go_quic_dispatcher, void* quic_server_session) {
    return CreateGoSession(go_quic_dispatcher, quic_server_session);
}

void DeleteGoSession_C(int64_t go_quic_dispatcher, int64_t go_quic_server_session) {
    DeleteGoSession(go_quic_dispatcher, go_quic_server_session);
}

int GetProof_C(int64_t go_proof_source, char* server_ip, size_t server_ip_sz, char* hostname, size_t hostname_sz, char* server_config, size_t server_config_sz, int quic_version, char* chlo_hash, size_t chlo_hash_len, char **out_signature, size_t *out_signature_sz) {
    return GetProof(go_proof_source, server_ip, server_ip_sz, hostname, hostname_sz, server_config, server_config_sz, quic_version, chlo_hash, chlo_hash_len, out_signature, out_signature_sz);
}

int64_t CreateIncomingDynamicStream_C(int64_t go_quic_server_session, uint32_t id, void* go_quic_simple_server_stream_go_wrapper) {
    return CreateIncomingDynamicStream(go_quic_server_session, id, go_quic_simple_server_stream_go_wrapper);
}

void UnregisterQuicServerStreamFromSession_C(int64_t go_stream) {
    UnregisterQuicServerStreamFromSession(go_stream);
}

void UnregisterQuicClientStreamFromSession_C(int64_t go_stream) {
    UnregisterQuicClientStreamFromSession(go_stream);
}

int64_t CreateGoQuicAlarm_C(void* go_quic_alarm_go_wrapper, void* clock, int64_t task_runner) {
    return CreateGoQuicAlarm(go_quic_alarm_go_wrapper, clock, task_runner);
}

void GoQuicAlarmSetImpl_C(int64_t go_quic_alarm, int64_t deadline) {
    GoQuicAlarmSetImpl(go_quic_alarm, deadline);
}

void GoQuicAlarmCancelImpl_C(int64_t go_quic_alarm) {
    GoQuicAlarmCancelImpl(go_quic_alarm);
}

void GoQuicAlarmDestroy_C(int64_t go_quic_alarm) {
    GoQuicAlarmDestroy(go_quic_alarm);
}

void GoQuicSpdyClientStreamOnInitialHeadersComplete_C(int64_t go_quic_spdy_client_stream, struct GoSpdyHeader* headers) {
    GoQuicSpdyClientStreamOnInitialHeadersComplete(go_quic_spdy_client_stream, headers);
}
void GoQuicSpdyClientStreamOnTrailingHeadersComplete_C(int64_t go_quic_spdy_client_stream, struct GoSpdyHeader* headers) {
    GoQuicSpdyClientStreamOnTrailingHeadersComplete(go_quic_spdy_client_stream, headers);
}
void GoQuicSpdyClientStreamOnDataAvailable_C(int64_t go_quic_spdy_client_stream, const char *data, uint32_t data_len, int is_closed) {
    GoQuicSpdyClientStreamOnDataAvailable(go_quic_spdy_client_stream, (void *)data, data_len, is_closed);
}
void GoQuicSpdyClientStreamOnClose_C(int64_t go_quic_spdy_client_stream) {
    GoQuicSpdyClientStreamOnClose(go_quic_spdy_client_stream);
}

void GoQuicSimpleServerStreamOnInitialHeadersComplete_C(int64_t go_quic_simple_server_stream, struct GoSpdyHeader* headers, const char *peer_address, uint32_t peer_address_len) {
    GoQuicSimpleServerStreamOnInitialHeadersComplete(go_quic_simple_server_stream, headers, (void *)peer_address, peer_address_len);
}
void GoQuicSimpleServerStreamOnDataAvailable_C(int64_t go_quic_simple_server_stream, const char *data, uint32_t data_len, int is_closed) {
    GoQuicSimpleServerStreamOnDataAvailable(go_quic_simple_server_stream, (void *)data, data_len, is_closed);
}

void GoQuicSimpleServerStreamOnClose_C(int64_t go_quic_simple_server_stream) {
    GoQuicSimpleServerStreamOnClose(go_quic_simple_server_stream);
}

int64_t NewProofVerifyJob_C(int64_t go_proof_verifier, int quic_version, const char* hostname, size_t hostname_len, const char* server_config, size_t server_config_len, const char* chlo_hash, size_t chlo_hash_len, const char* cert_sct, size_t cert_sct_len, const char* signature, size_t signature_len) {
    return NewProofVerifyJob(go_proof_verifier, quic_version, (void *)hostname, hostname_len, (void *)server_config, server_config_len, (void *)chlo_hash, chlo_hash_len, (void *)cert_sct, cert_sct_len, (void *)signature, signature_len);
}

void ProofVerifyJobAddCert_C(int64_t job, const char* cert, size_t cert_len) {
    ProofVerifyJobAddCert(job, (void *)cert, cert_len);
}

int ProofVerifyJobVerifyProof_C(int64_t job) {
    return ProofVerifyJobVerifyProof(job);
}

void ReleaseClientWriter_C(int64_t go_client_writer) {
    ReleaseClientWriter(go_client_writer);
}

void ReleaseServerWriter_C(int64_t go_server_writer) {
    ReleaseServerWriter(go_server_writer);
}

void ReleaseQuicDispatcher_C(int64_t go_quic_dispatcher) {
    ReleaseQuicDispatcher(go_quic_dispatcher);
}

void ReleaseTaskRunner_C(int64_t go_task_runner) {
    ReleaseTaskRunner(go_task_runner);
}

void ReleaseProofVerifier_C(int64_t go_proof_verifier) {
    ReleaseProofVerifier(go_proof_verifier);
}

void ReleaseProofSource_C(int64_t go_proof_source) {
    ReleaseProofSource(go_proof_source);
}
