// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// NOTE: This code is not shared between Google and Chrome.

#ifndef GO_QUIC_SPDY_CLIENT_STREAM_H_
#define GO_QUIC_SPDY_CLIENT_STREAM_H_

#include <string>

#include "net/quic/core/quic_spdy_stream.h"
#include "go_structs.h"

namespace net {

class GoQuicClientSession;

// All this does right now is send an SPDY request, and aggregate the
// SPDY response.
class GoQuicSpdyClientStream : public QuicSpdyStream {
 public:
  GoQuicSpdyClientStream(QuicStreamId id, GoQuicClientSession* session);
  ~GoQuicSpdyClientStream() override;

  void SetGoQuicClientStream(GoPtr go_quic_client_stream);

  // Override the base class to close the write side as soon as we get a
  // response.
  // SPDY/HTTP does not support bidirectional streaming.
  void OnStreamFrame(const QuicStreamFrame& frame) override;

  // Override the base class to parse and store headers.
  void OnInitialHeadersComplete(bool fin, size_t frame_len) override;

  // Override the base class to parse and store headers.
  void OnInitialHeadersComplete(bool fin,
                                 size_t frame_len,
                                 const QuicHeaderList& header_list) override;

  // Override the base class to parse and store trailers.
  void OnTrailingHeadersComplete(bool fin,
                                 size_t frame_len,
                                 const QuicHeaderList& header_list) override;

  // ReliableQuicStream implementation called by the session when there's
  // data for us.
  void OnDataAvailable() override;

  void OnClose() override;

  // While the server's SetPriority shouldn't be called externally, the creator
  // of client-side streams should be able to set the priority.
  using QuicSpdyStream::SetPriority;

  void set_allow_bidirectional_data(bool value) {
    allow_bidirectional_data_ = value;
  }

  bool allow_bidirectional_data() const { return allow_bidirectional_data_; }

 private:
  // The parsed headers received from the server.
  SpdyHeaderBlock response_headers_;

  // The parsed content-length, or -1 if none is specified.
  int64_t content_length_;
  int response_code_;
  size_t header_bytes_read_;
  GoPtr go_quic_client_stream_;
  // When true allows the sending of a request to continue while the response is
  // arriving.
  // XXX: Currently not supported in goquic
  bool allow_bidirectional_data_;

  GoQuicClientSession* session_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicSpdyClientStream);
};

}  // namespace net

#endif  // GO_QUIC_SPDY_CLIENT_STREAM_H_
