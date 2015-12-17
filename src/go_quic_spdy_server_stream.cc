#include "go_quic_spdy_server_stream.h"
#include "net/quic/quic_session.h"
#include "base/strings/string_piece.h"

#include "go_functions.h"

namespace net {
namespace tools {

GoQuicSpdyServerStream::GoQuicSpdyServerStream(QuicStreamId id,
                                                                 QuicSpdySession* session)
  : QuicSpdyStream(id, session) {}

GoQuicSpdyServerStream::~GoQuicSpdyServerStream() {
  UnregisterQuicServerStreamFromSession_C(go_quic_spdy_server_stream_);
}

void GoQuicSpdyServerStream::SetGoQuicSpdyServerStream(void* go_quic_spdy_server_stream) {
  go_quic_spdy_server_stream_ = go_quic_spdy_server_stream;
}

void GoQuicSpdyServerStream::OnInitialHeadersComplete(bool fin,
                                                      size_t frame_len) {
  QuicSpdyStream::OnInitialHeadersComplete(fin, frame_len);

  GoQuicSpdyServerStreamOnInitialHeadersComplete_C(go_quic_spdy_server_stream_,
                                                   decompressed_headers().data(),
                                                   decompressed_headers().length());
  MarkHeadersConsumed(decompressed_headers().length());
}

void GoQuicSpdyServerStream::OnTrailingHeadersComplete(bool fin,
                                                       size_t frame_len) {
  LOG(DFATAL) << "Server does not support receiving Trailers.";
  // TODO(hodduc): Should Send error response
}

void GoQuicSpdyServerStream::OnDataAvailable() {
  while (HasBytesToRead()) {
    struct iovec iov;
    if (GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      break;
    }
    DVLOG(1) << "Processed " << iov.iov_len << " bytes for stream " << id();
    body_.append(static_cast<char*>(iov.iov_base), iov.iov_len);

    MarkConsumed(iov.iov_len);
  }
  if (!sequencer()->IsClosed()) {
    sequencer()->SetUnblocked();
    return;
  }

  // If the sequencer is closed, then all the body, including the fin, has been
  // consumed.
  OnFinRead();

  if (write_side_closed() || fin_buffered()) {
    return;
  }

  GoQuicSpdyServerStreamOnDataAvailable_C(go_quic_spdy_server_stream_, body_.data(), body_.length(), sequencer()->IsClosed());
}

void GoQuicSpdyServerStream::WriteOrBufferData_(
    base::StringPiece data, bool fin, net::QuicAckListenerInterface* ack_listener) {
  WriteOrBufferData(data, fin, ack_listener);
}

void GoQuicSpdyServerStream::OnClose() {
  net::QuicSpdyStream::OnClose();

  GoQuicSpdyServerStreamOnClose_C(go_quic_spdy_server_stream_);
}

}  // namespace tools
}  // namespace net
