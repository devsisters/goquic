// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "go_quic_simple_server_session.h"
#include "go_quic_simple_server_stream.h"
#include "go_functions.h"

#include "base/logging.h"
#include "net/quic/proto/cached_network_parameters.pb.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_spdy_session.h"
#include "net/quic/reliable_quic_stream.h"

namespace net {

GoQuicSimpleServerSession::GoQuicSimpleServerSession(
    const QuicConfig& config,
    QuicConnection* connection,
    GoQuicServerSessionVisitor* visitor,
    const QuicCryptoServerConfig* crypto_config)
    : GoQuicServerSessionBase(config, connection, visitor, crypto_config) {}

GoQuicSimpleServerSession::~GoQuicSimpleServerSession() {}

QuicCryptoServerStreamBase*
GoQuicSimpleServerSession::CreateQuicCryptoServerStream(
    const QuicCryptoServerConfig* crypto_config) {
  return new QuicCryptoServerStream(crypto_config, this);
}

QuicSpdyStream* GoQuicSimpleServerSession::CreateIncomingDynamicStream(
    QuicStreamId id) {
  if (!ShouldCreateIncomingDynamicStream(id)) {
    return nullptr;
  }

  GoQuicSimpleServerStream* stream = new GoQuicSimpleServerStream(
      id, this);  // Managed by stream_map_ of QuicSession. Deleted by
                  // STLDeleteElements function call in QuicSession
  stream->SetGoQuicSimpleServerStream(
      CreateIncomingDynamicStream_C(go_session_, id, stream));

  return stream;
}

GoQuicSimpleServerStream* GoQuicSimpleServerSession::CreateOutgoingDynamicStream(
    SpdyPriority priority) {
  if (!ShouldCreateOutgoingDynamicStream()) {
    return nullptr;
  }

  GoQuicSimpleServerStream* stream =
      new GoQuicSimpleServerStream(GetNextOutgoingStreamId(), this);
  stream->SetPriority(priority);
  ActivateStream(stream);
  return stream;
}

}  // namespace net
