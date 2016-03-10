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

#include "base/containers/hash_tables.h"
#include "base/macros.h"
#include "base/memory/scoped_ptr.h"
#include "net/quic/quic_crypto_server_stream.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_spdy_session.h"

#include "go_quic_server_session_base.h"
#include "go_quic_simple_server_stream.h"

namespace net {

class QuicBlockedWriterInterface;
class QuicConfig;
class QuicConnection;
class QuicCryptoServerConfig;
class ReliableQuicStream;

class GoQuicSimpleServerSession : public GoQuicServerSessionBase {
 public:
  GoQuicSimpleServerSession(const QuicConfig& config,
                            QuicConnection* connection,
                            GoQuicServerSessionVisitor* visitor,
                            const QuicCryptoServerConfig* crypto_config);

  ~GoQuicSimpleServerSession() override;

 protected:
  // QuicSession methods:
  QuicSpdyStream* CreateIncomingDynamicStream(QuicStreamId id) override;
  GoQuicSimpleServerStream* CreateOutgoingDynamicStream(
      SpdyPriority priority) override;

  QuicCryptoServerStreamBase* CreateQuicCryptoServerStream(
      const QuicCryptoServerConfig* crypto_config) override;

 private:
  DISALLOW_COPY_AND_ASSIGN(GoQuicSimpleServerSession);
};

}  // namespace net

#endif  // GO_QUIC_SIMPLE_SERVER_SESSION_H_
