#include "go_quic_spdy_server_stream_go_wrapper.h"
#include "net/quic/quic_session.h"
#include "net/quic/quic_data_stream.h"

#include "go_functions.h"

GoQuicSpdyServerStreamGoWrapper::GoQuicSpdyServerStreamGoWrapper(net::QuicStreamId id, net::QuicSession* session, void* go_quic_spdy_server_stream)
  : net::QuicDataStream(id, session),
    go_quic_spdy_server_stream_(go_quic_spdy_server_stream) {
}

GoQuicSpdyServerStreamGoWrapper::~GoQuicSpdyServerStreamGoWrapper() {
}
// TODO(hodduc) more more implementation
//
uint32 GoQuicSpdyServerStreamGoWrapper::ProcessData(const char* data, uint32 data_len) {
  if (data_len > INT_MAX) {
    LOG(DFATAL) << "Data length too long: " << data_len;
    return 0;
  }

  uint32_t ret_data_len = DataStreamProcessorProcessData_C(go_quic_spdy_server_stream_, data, data_len);

  return ret_data_len;
}
