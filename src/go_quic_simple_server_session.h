// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A toy server specific QuicSession subclass.

#ifndef GO_QUIC_SIMPLE_SERVER_SESSION_H_
#define GO_QUIC_SIMPLE_SERVER_SESSION_H_

#include <stdint.h>

#include <set>
#include <string>
#include <vector>

#include "base/macros.h"
#include "net/quic/core/quic_crypto_server_stream.h"
#include "net/quic/core/quic_protocol.h"
#include "net/quic/core/quic_server_session_base.h"
#include "net/quic/core/quic_spdy_session.h"

#include "go_quic_simple_server_stream.h"

namespace net {

class QuicBlockedWriterInterface;
class QuicConfig;
class QuicConnection;
class QuicCryptoServerConfig;
class ReliableQuicStream;

class GoQuicSimpleServerSession : public QuicServerSessionBase {
 public:
  GoQuicSimpleServerSession(const QuicConfig& config,
                            QuicConnection* connection,
                            QuicServerSessionBase::Visitor* visitor,
                            QuicCryptoServerStream::Helper* helper,
                            const QuicCryptoServerConfig* crypto_config,
                            QuicCompressedCertsCache* compressed_certs_cache);

  ~GoQuicSimpleServerSession() override;

  void SetGoSession(GoPtr go_quic_dispatcher, GoPtr go_session) {
    go_quic_dispatcher_ = go_quic_dispatcher;
    go_session_ = go_session;
  }

 protected:
  // QuicSession methods:
  QuicSpdyStream* CreateIncomingDynamicStream(QuicStreamId id) override;
  GoQuicSimpleServerStream* CreateOutgoingDynamicStream(
      SpdyPriority priority) override;

  QuicCryptoServerStreamBase* CreateQuicCryptoServerStream(
      const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache) override;

 private:

  GoPtr go_session_;
  GoPtr go_quic_dispatcher_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicSimpleServerSession);
};

}  // namespace net

#endif  // GO_QUIC_SIMPLE_SERVER_SESSION_H_
