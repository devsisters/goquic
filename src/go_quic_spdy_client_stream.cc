// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "go_quic_spdy_client_stream.h"

#include "net/base/net_errors.h"
#include "net/quic/core/quic_session.h"
#include "net/quic/core/quic_write_blocked_list.h"
#include "net/quic/core/spdy_utils.h"

#include "go_functions.h"
#include "go_quic_client_session.h"
#include "go_utils.h"

namespace net {

GoQuicSpdyClientStream::GoQuicSpdyClientStream(QuicStreamId id,
                                               GoQuicClientSession* session)
    : QuicSpdyStream(id, session),
      content_length_(-1),
      response_code_(0),
      header_bytes_read_(0),
      allow_bidirectional_data_(false),
      session_(session) {}

GoQuicSpdyClientStream::~GoQuicSpdyClientStream() {
  UnregisterQuicClientStreamFromSession_C(go_quic_client_stream_);
}

void GoQuicSpdyClientStream::SetGoQuicClientStream(
    GoPtr go_quic_client_stream) {
  go_quic_client_stream_ = go_quic_client_stream;
}

void GoQuicSpdyClientStream::OnStreamFrame(const QuicStreamFrame& frame) {
  if (!allow_bidirectional_data_ && !write_side_closed()) {
    DVLOG(1) << "Got a response before the request was complete.  "
             << "Aborting request.";
    CloseWriteSide();
  }
  QuicSpdyStream::OnStreamFrame(frame);
}

void GoQuicSpdyClientStream::OnInitialHeadersComplete(bool fin,
                                                      size_t frame_len) {
  QuicSpdyStream::OnInitialHeadersComplete(fin, frame_len);

  DCHECK(headers_decompressed());
  header_bytes_read_ += frame_len;
  if (!SpdyUtils::ParseHeaders(decompressed_headers().data(),
                               decompressed_headers().length(),
                               &content_length_, &response_headers_)) {
    DLOG(ERROR) << "Failed to parse headers: " << decompressed_headers();
    Reset(QUIC_BAD_APPLICATION_PAYLOAD);
    return;
  }

  if (!ParseHeaderStatusCode(response_headers_, &response_code_)) {
    DLOG(ERROR) << "Received invalid response code: "
                << response_headers_[":status"].as_string();
    Reset(QUIC_BAD_APPLICATION_PAYLOAD);
    return;
  }

  auto hdr = CreateGoSpdyHeader(response_headers_);
  GoQuicSpdyClientStreamOnInitialHeadersComplete_C(go_quic_client_stream_, hdr);
  DeleteGoSpdyHeader(hdr);

  MarkHeadersConsumed(decompressed_headers().length());

  session_->OnInitialHeadersComplete(id(), response_headers_);
}

void GoQuicSpdyClientStream::OnInitialHeadersComplete(
    bool fin,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  QuicSpdyStream::OnInitialHeadersComplete(fin, frame_len, header_list);

  DCHECK(headers_decompressed());
  header_bytes_read_ += frame_len;
  if (!SpdyUtils::CopyAndValidateHeaders(header_list, &content_length_,
                                         &response_headers_)) {
    DLOG(ERROR) << "Failed to parse header list: " << header_list.DebugString();
    Reset(QUIC_BAD_APPLICATION_PAYLOAD);
    return;
  }

  if (!ParseHeaderStatusCode(response_headers_, &response_code_)) {
    DLOG(ERROR) << "Received invalid response code: "
                << response_headers_[":status"].as_string();
    Reset(QUIC_BAD_APPLICATION_PAYLOAD);
    return;
  }

  auto hdr = CreateGoSpdyHeader(response_headers_);
  GoQuicSpdyClientStreamOnInitialHeadersComplete_C(go_quic_client_stream_, hdr);
  DeleteGoSpdyHeader(hdr);

  ConsumeHeaderList();
  DVLOG(1) << "headers complete for stream " << id();

  session_->OnInitialHeadersComplete(id(), response_headers_);
}

void GoQuicSpdyClientStream::OnTrailingHeadersComplete(
    bool fin,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  QuicSpdyStream::OnTrailingHeadersComplete(fin, frame_len, header_list);

  auto hdr = CreateGoSpdyHeader(received_trailers());
  GoQuicSpdyClientStreamOnTrailingHeadersComplete_C(go_quic_client_stream_, hdr);
  DeleteGoSpdyHeader(hdr);

  MarkTrailersConsumed(decompressed_trailers().length());
}

void GoQuicSpdyClientStream::OnDataAvailable() {
  std::string buf;

  while (HasBytesToRead()) {
    struct iovec iov;
    if (GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      break;
    }
    DVLOG(1) << "Client processed " << iov.iov_len << " bytes for stream "
             << id();

    buf.append(static_cast<char*>(iov.iov_base), iov.iov_len);
    MarkConsumed(iov.iov_len);
  }
  if (sequencer()->IsClosed()) {
    OnFinRead();
  } else {
    sequencer()->SetUnblocked();
  }

  // XXX(hodduc): We can call OnDataAvailable every times(with iov) or just once. Which one is better???
  GoQuicSpdyClientStreamOnDataAvailable_C(go_quic_client_stream_,
                                          buf.data(),
                                          buf.size(),
                                          sequencer()->IsClosed());
}

void GoQuicSpdyClientStream::OnClose() {
  QuicSpdyStream::OnClose();
  GoQuicSpdyClientStreamOnClose_C(go_quic_client_stream_);
}

}  // namespace net
