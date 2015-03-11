// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "go_quic_reliable_client_stream.h"

#include "net/base/net_errors.h"
#include "net/quic/quic_session.h"
#include "net/quic/quic_write_blocked_list.h"

#include "go_functions.h"

namespace net {

GoQuicReliableClientStream::GoQuicReliableClientStream(QuicStreamId id,
                                                       QuicSession* session)
    : QuicDataStream(id, session) {
}

GoQuicReliableClientStream::~GoQuicReliableClientStream() {
  UnregisterQuicClientStreamFromSession_C(go_quic_client_stream_);
}

void GoQuicReliableClientStream::SetGoQuicClientStream(void* go_quic_client_stream) {
  go_quic_client_stream_ = go_quic_client_stream;
}

uint32 GoQuicReliableClientStream::ProcessData(const char* data,
                                             uint32 data_len) {
  uint32_t ret_data_len = DataStreamProcessorProcessData_C(go_quic_client_stream_, data, data_len);
  return ret_data_len;
}

void GoQuicReliableClientStream::OnClose() {
  QuicDataStream::OnClose();
  DataStreamProcessorOnClose_C(go_quic_client_stream_);
}

void GoQuicReliableClientStream::WriteOrBufferData_(
    base::StringPiece buffer, bool fin, net::QuicAckNotifier::DelegateInterface* delegate) {
  WriteOrBufferData(buffer, fin, delegate);
}

}  // namespace net
