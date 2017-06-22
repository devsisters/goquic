#include "go_quic_simple_server_stream.h"
#include "go_functions.h"
#include "go_utils.h"

#include <utility>

#include "net/quic/core/quic_session.h"
#include "net/quic/core/quic_spdy_session.h"
#include "net/quic/core/spdy_utils.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_number_conversions.h"

namespace net {

GoQuicSimpleServerStream::GoQuicSimpleServerStream(QuicStreamId id,
                                                   QuicSpdySession* session)
    : QuicSpdyStream(id, session), content_length_(-1) {}

GoQuicSimpleServerStream::~GoQuicSimpleServerStream() {
  UnregisterQuicServerStreamFromSession_C(go_quic_simple_server_stream_);
}

void GoQuicSimpleServerStream::SetGoQuicSimpleServerStream(
    GoPtr go_quic_simple_server_stream) {
  go_quic_simple_server_stream_ = go_quic_simple_server_stream;
}

void GoQuicSimpleServerStream::OnInitialHeadersComplete(bool fin,
                                                        size_t frame_len) {
  QuicSpdyStream::OnInitialHeadersComplete(fin, frame_len);
  if (!SpdyUtils::ParseHeaders(decompressed_headers().data(),
                               decompressed_headers().length(),
                               &content_length_, &request_headers_)) {
    DVLOG(1) << "Invalid headers";
    SendErrorResponse();
  }

  auto peer_address = spdy_session()->connection()->peer_address().ToString();
  auto hdr = CreateGoSpdyHeader(request_headers_);
  GoQuicSimpleServerStreamOnInitialHeadersComplete_C(go_quic_simple_server_stream_, hdr, peer_address.data(), peer_address.length());
  DeleteGoSpdyHeader(hdr);

  MarkHeadersConsumed(decompressed_headers().length());
}

void GoQuicSimpleServerStream::OnInitialHeadersComplete(
    bool fin,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  QuicSpdyStream::OnInitialHeadersComplete(fin, frame_len, header_list);
  if (!SpdyUtils::CopyAndValidateHeaders(header_list, &content_length_,
                                         &request_headers_)) {
    DVLOG(1) << "Invalid headers";
    SendErrorResponse();
  }

  auto peer_address = spdy_session()->connection()->peer_address().ToString();
  auto hdr = CreateGoSpdyHeader(request_headers_);
  GoQuicSimpleServerStreamOnInitialHeadersComplete_C(go_quic_simple_server_stream_, hdr, peer_address.data(), peer_address.length());
  DeleteGoSpdyHeader(hdr);

  ConsumeHeaderList();
}

void GoQuicSimpleServerStream::OnTrailingHeadersComplete(bool fin,
                                                         size_t frame_len) {
  QUIC_BUG << "Server does not support receiving Trailers.";
  SendErrorResponse();
}

void GoQuicSimpleServerStream::OnTrailingHeadersComplete(
    bool fin,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  QUIC_BUG << "Server does not support receiving Trailers.";
  SendErrorResponse();
}

void GoQuicSimpleServerStream::OnDataAvailable() {
  while (HasBytesToRead()) {
    struct iovec iov;
    if (GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      break;
    }
    DVLOG(1) << "Processed " << iov.iov_len << " bytes for stream " << id();
    body_.append(static_cast<char*>(iov.iov_base), iov.iov_len);

    if (content_length_ >= 0 &&
        body_.size() > static_cast<uint64_t>(content_length_)) {
      DVLOG(1) << "Body size (" << body_.size() << ") > content length ("
               << content_length_ << ").";
      SendErrorResponse();
      return;
    }
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

  if (request_headers_.empty()) {
    DVLOG(1) << "Request headers empty.";
    SendErrorResponse();
    return;
  }

  if (content_length_ > 0 &&
      static_cast<uint64_t>(content_length_) != body_.size()) {
    DVLOG(1) << "Content length (" << content_length_ << ") != body size ("
             << body_.size() << ").";
    SendErrorResponse();
    return;
  }

  GoQuicSimpleServerStreamOnDataAvailable_C(go_quic_simple_server_stream_,
                                            body_.data(), body_.length(),
                                            sequencer()->IsClosed());
}

void GoQuicSimpleServerStream::SendErrorResponse() {
  DVLOG(1) << "Sending error response for stream " << id();
  SpdyHeaderBlock headers;
  headers[":status"] = "500";
  headers["content-length"] = base::UintToString(strlen(kErrorResponseBody));

  WriteHeaders(std::move(headers), false, nullptr);
  WriteOrBufferBody(kErrorResponseBody, true, nullptr);
}

size_t GoQuicSimpleServerStream::WriteHeaders(
    SpdyHeaderBlock header_block,
    bool fin,
    QuicAckListenerInterface* ack_notifier_delegate) {

  if (!reading_stopped()) {
    StopReading();
  }
  return QuicSpdyStream::WriteHeaders(std::move(header_block), fin, ack_notifier_delegate);
}

void GoQuicSimpleServerStream::OnClose() {
  net::QuicSpdyStream::OnClose();

  GoQuicSimpleServerStreamOnClose_C(go_quic_simple_server_stream_);
}

const char* const GoQuicSimpleServerStream::kErrorResponseBody = "bad";

}  // namespace net
