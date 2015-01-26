#include "go_functions.h"

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#include "_cgo_export.h"

void WriteToUDP_C(void* go_udp_conn, void* peer_address, void* buffer, size_t buf_len, void* quic_server_packet_writer, void* go_task_runner) {
    WriteToUDP(go_udp_conn, peer_address, buffer, buf_len, quic_server_packet_writer, go_task_runner);
}

void* CreateGoSession_C(void* go_quic_dispatcher, void* quic_server_session) {
    return CreateGoSession(go_quic_dispatcher, quic_server_session);
}

void* CreateIncomingDataStream_C(void* go_quic_server_session, uint32_t id, void* go_quic_spdy_server_stream_go_wrapper) {
    return CreateIncomingDataStream(go_quic_server_session, id, go_quic_spdy_server_stream_go_wrapper);
}

uint32_t DataStreamProcessorProcessData_C(void* go_data_stream_processor, const char *data, uint32_t data_len) {
    return DataStreamProcessorProcessData(go_data_stream_processor, (void *)data, data_len);
}

void DataStreamProcessorOnFinRead_C(void* go_data_stream_processor) {
    DataStreamProcessorOnFinRead(go_data_stream_processor);
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
