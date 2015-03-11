#include "go_quic_spdy_server_stream_go_wrapper.h"
#include "net/quic/quic_session.h"
#include "net/quic/quic_data_stream.h"
#include "net/quic/quic_ack_notifier.h"
#include "base/strings/string_piece.h"

#include "go_functions.h"

GoQuicSpdyServerStreamGoWrapper::GoQuicSpdyServerStreamGoWrapper(net::QuicStreamId id, net::QuicSession* session)
  : net::QuicDataStream(id, session) {
}

GoQuicSpdyServerStreamGoWrapper::~GoQuicSpdyServerStreamGoWrapper() {
}

void GoQuicSpdyServerStreamGoWrapper::SetGoQuicSpdyServerStream(void* go_quic_spdy_server_stream) {
  go_quic_spdy_server_stream_ = go_quic_spdy_server_stream;
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

void GoQuicSpdyServerStreamGoWrapper::OnFinRead() {
  ReliableQuicStream::OnFinRead();
  if (write_side_closed() || fin_buffered()) {
    return;
  }

  DataStreamProcessorOnFinRead_C(go_quic_spdy_server_stream_);
}

void GoQuicSpdyServerStreamGoWrapper::CloseReadSide_() {
  ReliableQuicStream::CloseReadSide();
}

void GoQuicSpdyServerStreamGoWrapper::WriteOrBufferData_(
    base::StringPiece buffer, bool fin, net::QuicAckNotifier::DelegateInterface* delegate) {
  WriteOrBufferData(buffer, fin, delegate);
}
