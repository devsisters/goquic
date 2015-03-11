#include "go_functions.h"

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#include "_cgo_export.h"

void WriteToUDP_C(void* go_udp_conn, void* peer_address, void* buffer, size_t buf_len, void* quic_server_packet_writer, void* go_task_runner) {
    WriteToUDP(go_udp_conn, peer_address, buffer, buf_len, quic_server_packet_writer, go_task_runner, 0);
}

void WriteToUDPSync_C(void* go_udp_conn, void* peer_address, void* buffer, size_t buf_len, void* quic_server_packet_writer, void* go_task_runner) {
    WriteToUDP(go_udp_conn, peer_address, buffer, buf_len, quic_server_packet_writer, go_task_runner, 1);
}

void* CreateGoSession_C(void* go_quic_dispatcher, void* quic_server_session) {
    return CreateGoSession(go_quic_dispatcher, quic_server_session);
}

void* DeleteGoSession_C(void* go_quic_dispatcher, void* go_quic_server_session) {
    DeleteGoSession(go_quic_dispatcher, go_quic_server_session);
}

int GetProof_C(void* go_quic_dispatcher, void* server_ip, char* hostname, size_t hostname_sz, char* server_config, size_t server_config_sz, int ecdsa_ok, char ***out_certs, int *out_certs_sz, size_t **out_certs_item_sz, char **out_signature, size_t *out_signature_sz) {
    return GetProof(go_quic_dispatcher, server_ip, hostname, hostname_sz, server_config, server_config_sz, ecdsa_ok, out_certs, out_certs_sz, out_certs_item_sz, out_signature, out_signature_sz);
}

void* CreateIncomingDataStream_C(void* go_quic_server_session, uint32_t id, void* go_quic_spdy_server_stream_go_wrapper) {
    return CreateIncomingDataStream(go_quic_server_session, id, go_quic_spdy_server_stream_go_wrapper);
}

uint32_t DataStreamProcessorProcessData_C(void* go_data_stream_processor, const char *data, uint32_t data_len) {
    return DataStreamProcessorProcessData(go_data_stream_processor, (void *)data, data_len, 1);
}

uint32_t DataStreamProcessorProcessDataClient_C(void* go_data_stream_processor, const char *data, uint32_t data_len) {
    return DataStreamProcessorProcessData(go_data_stream_processor, (void *)data, data_len, 0);
}

void DataStreamProcessorOnFinRead_C(void* go_data_stream_processor) {
    DataStreamProcessorOnFinRead(go_data_stream_processor, 1);
}

void DataStreamProcessorOnClose_C(void* go_data_stream_processor) {
    DataStreamProcessorOnClose(go_data_stream_processor, 0);
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

void GoQuicAlarmSetImpl_C(void *go_quic_alarm, int64_t deadline, int64_t now) {
    GoQuicAlarmSetImpl(go_quic_alarm, deadline, now);
}

void GoQuicAlarmCancelImpl_C(void *go_quic_alarm, int64_t now) {
    GoQuicAlarmCancelImpl(go_quic_alarm, now);
}

void GoQuicAlarmDestroy_C(void *go_quic_alarm) {
    GoQuicAlarmDestroy(go_quic_alarm);
}
