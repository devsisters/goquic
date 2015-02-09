// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// NOTE: This code is not shared between Google and Chrome.

#ifndef NET_QUIC_QUIC_RELIABLE_CLIENT_STREAM_H_
#define NET_QUIC_QUIC_RELIABLE_CLIENT_STREAM_H_

#include "net/base/ip_endpoint.h"
#include "net/quic/quic_data_stream.h"

namespace net {

class GoQuicClientSession;

// A client-initiated ReliableQuicStream.  Instances of this class
// are owned by the GoQuicClientSession which created them.
class NET_EXPORT_PRIVATE GoQuicReliableClientStream : public QuicDataStream {
 public:
  GoQuicReliableClientStream(QuicStreamId id, QuicSession* session);
  ~GoQuicReliableClientStream() override;

  void SetGoQuicClientStream(void* go_quic_client_stream);

  // QuicDataStream
  uint32 ProcessData(const char* data, uint32 data_len) override;

  // we need a proxy because ReliableQuicStream::WriteOrBufferData is protected.
  // we could access this function from C (go) side.
  void WriteOrBufferData_(base::StringPiece buffer, bool fin, net::QuicAckNotifier::DelegateInterface* delegate);

  // While the server's set_priority shouldn't be called externally, the creator
  // of client-side streams should be able to set the priority.
  using QuicDataStream::set_priority;


 private:

  void* go_quic_client_stream_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicReliableClientStream);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_RELIABLE_CLIENT_STREAM_H_
