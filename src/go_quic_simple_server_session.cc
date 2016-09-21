// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "go_quic_simple_server_session.h"
#include "go_quic_simple_server_stream.h"
#include "go_functions.h"

#include "base/logging.h"
#include "net/quic/core/proto/cached_network_parameters.pb.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_spdy_session.h"
#include "net/quic/core/reliable_quic_stream.h"

using std::string;

namespace net {

GoQuicSimpleServerSession::GoQuicSimpleServerSession(
    const QuicConfig& config,
    QuicConnection* connection,
    QuicServerSessionBase::Visitor* visitor,
    QuicCryptoServerStream::Helper* helper,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache)
    : QuicServerSessionBase(config,
                            connection,
                            visitor,
                            helper,
                            crypto_config,
                            compressed_certs_cache) {}

GoQuicSimpleServerSession::~GoQuicSimpleServerSession() {
  DeleteGoSession_C(go_quic_dispatcher_, go_session_);
}

QuicCryptoServerStreamBase*
GoQuicSimpleServerSession::CreateQuicCryptoServerStream(
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache) {
  return new QuicCryptoServerStream(crypto_config, compressed_certs_cache,
                                    FLAGS_enable_quic_stateless_reject_support,
                                    this, stream_helper());
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
  ActivateStream(stream);

  return stream;
}

GoQuicSimpleServerStream* GoQuicSimpleServerSession::CreateOutgoingDynamicStream(
    SpdyPriority priority) {
  if (!ShouldCreateOutgoingDynamicStream()) {
    return nullptr;
  }

  // Should not be called!

  GoQuicSimpleServerStream* stream =
      new GoQuicSimpleServerStream(GetNextOutgoingStreamId(), this);
  stream->SetPriority(priority);
  ActivateStream(stream);
  return stream;
}

}  // namespace net
