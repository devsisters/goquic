// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// NOTE: This code is not shared between Google and Chrome.

#ifndef GO_QUIC_SPDY_CLIENT_STREAM_H_
#define GO_QUIC_SPDY_CLIENT_STREAM_H_

#include <string>

#include "net/quic/quic_spdy_stream.h"

namespace net {
namespace tools {

class GoQuicClientSession;

// All this does right now is send an SPDY request, and aggregate the
// SPDY response.
class NET_EXPORT_PRIVATE GoQuicSpdyClientStream : public QuicSpdyStream {
 public:
  GoQuicSpdyClientStream(QuicStreamId id, GoQuicClientSession* session);
  ~GoQuicSpdyClientStream() override;

  void SetGoQuicClientStream(void* go_quic_client_stream);

  // Override the base class to close the write side as soon as we get a
  // response.
  // SPDY/HTTP does not support bidirectional streaming.
  void OnStreamFrame(const QuicStreamFrame& frame) override;

  // Override the base class to store the size of the headers.
  void OnStreamHeadersComplete(bool fin, size_t frame_len) override;

  // ReliableQuicStream implementation called by the session when there's
  // data for us.
  void OnDataAvailable() override;

  void OnClose() override;

  // we need a proxy because ReliableQuicStream::WriteOrBufferData is protected.
  // we could access this function from C (go) side.
  void WriteOrBufferData_(base::StringPiece data, bool fin, net::QuicAckListenerInterface* ack_listener);

  // While the server's set_priority shouldn't be called externally, the creator
  // of client-side streams should be able to set the priority.
  using QuicSpdyStream::set_priority;

  bool allow_bidirectional_data() const { return allow_bidirectional_data_; }

 private:
  std::string data_;
  // When true allows the sending of a request to continue while the response is
  // arriving.
  // XXX: Currently not supported in goquic
  bool allow_bidirectional_data_;

  void* go_quic_client_stream_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicSpdyClientStream);
};

}  // namespace tools
}  // namespace net

#endif  // GO_QUIC_SPDY_CLIENT_STREAM_H_
