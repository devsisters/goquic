#include "go_functions.h"

#include <stddef.h>
#include <stdint.h>

#include "_cgo_export.h"

void WriteToUDP_C(void* go_udp_conn, void* peer_address, void* buffer, size_t buf_len) {
    WriteToUDP(go_udp_conn, peer_address, buffer, buf_len);
}

void* CreateGoSession_C(void* go_quic_dispatcher, void* quic_server_session) {
    return CreateGoSession(go_quic_dispatcher, quic_server_session);
}

void* CreateIncomingDataStream_C(void* go_quic_server_session, uint32_t id) {
    return CreateIncomingDataStream(go_quic_server_session, id);
}

uint32_t DataStreamProcessorProcessData_C(void* go_data_stream_processor, const char *data, uint32_t data_len) {
    return DataStreamProcessorProcessData(go_data_stream_processor, data, data_len);
}

void DataStreamProcessorOnFinRead_C(void* go_data_stream_processor) {
    DataStreamProcessorOnFinRead(go_data_stream_processor);
}
