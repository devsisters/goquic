#include "go_quic_spdy_server_stream_go_wrapper.h"
#include "net/quic/quic_session.h"
#include "net/quic/quic_data_stream.h"

GoQuicSpdyServerStreamGoWrapper::GoQuicSpdyServerStreamGoWrapper(net::QuicStreamId id, net::QuicSession* session, void* go_quic_spdy_server_stream)
  : net::QuicDataStream(id, session),
    go_quic_spdy_server_stream_(go_quic_spdy_server_stream) {
  }

GoQuicSpdyServerStreamGoWrapper::~GoQuicSpdyServerStreamGoWrapper() {
}
// TODO(hodduc) more more implementation
