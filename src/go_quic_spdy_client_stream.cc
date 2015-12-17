// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "go_quic_spdy_client_stream.h"

#include "net/base/net_errors.h"
#include "net/quic/quic_session.h"
#include "net/quic/quic_write_blocked_list.h"

#include "go_functions.h"
#include "go_quic_client_session.h"

namespace net {
namespace tools {

GoQuicSpdyClientStream::GoQuicSpdyClientStream(QuicStreamId id,
                                               GoQuicClientSession* session)
    : QuicSpdyStream(id, session),
      allow_bidirectional_data_(false) {}

GoQuicSpdyClientStream::~GoQuicSpdyClientStream() {
  UnregisterQuicClientStreamFromSession_C(go_quic_client_stream_);
}

void GoQuicSpdyClientStream::SetGoQuicClientStream(void* go_quic_client_stream) {
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
  GoQuicSpdyClientStreamOnInitialHeadersComplete_C(go_quic_client_stream_,
                                                   decompressed_headers().data(),
                                                   decompressed_headers().length());
  MarkHeadersConsumed(decompressed_headers().length());
}

void GoQuicSpdyClientStream::OnTrailingHeadersComplete(bool fin,
                                                       size_t frame_len) {
  QuicSpdyStream::OnTrailingHeadersComplete(fin, frame_len);
  GoQuicSpdyClientStreamOnTrailingHeadersComplete_C(go_quic_client_stream_,
                                                    decompressed_trailers().data(),
                                                    decompressed_trailers().length());
  MarkTrailersConsumed(decompressed_trailers().length());
}

void GoQuicSpdyClientStream::OnDataAvailable() {
  while (HasBytesToRead()) {
    struct iovec iov;
    if (GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      break;
    }
    DVLOG(1) << "Client processed " << iov.iov_len << " bytes for stream "
             << id();
    data_.append(static_cast<char*>(iov.iov_base), iov.iov_len);

    MarkConsumed(iov.iov_len);
  }
  if (sequencer()->IsClosed()) {
    OnFinRead();
  } else {
    sequencer()->SetUnblocked();
  }

  GoQuicSpdyClientStreamOnDataAvailable_C(go_quic_client_stream_, data_.data(), data_.length(), sequencer()->IsClosed());
}

void GoQuicSpdyClientStream::OnClose() {
  QuicSpdyStream::OnClose();
  GoQuicSpdyClientStreamOnClose_C(go_quic_client_stream_);
}

void GoQuicSpdyClientStream::WriteOrBufferData_(
    base::StringPiece data, bool fin, net::QuicAckListenerInterface* ack_listener) {
  WriteOrBufferData(data, fin, ack_listener);
}

}  // namespace tools
}  // namespace net
