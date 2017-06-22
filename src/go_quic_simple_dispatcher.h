// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef GO_QUIC_SIMPLE_DISPATCHER_H_
#define GO_QUIC_SIMPLE_DISPATCHER_H_

#include "go_quic_dispatcher.h"
#include "go_structs.h"

namespace net {

class GoQuicSimpleDispatcher : public GoQuicDispatcher {
 public:
  GoQuicSimpleDispatcher(
      const QuicConfig& config,
      const QuicCryptoServerConfig* crypto_config,
      QuicVersionManager* version_manager,
      std::unique_ptr<QuicConnectionHelperInterface> helper,
      std::unique_ptr<QuicCryptoServerStream::Helper> session_helper,
      std::unique_ptr<QuicAlarmFactory> alarm_factory,
      GoPtr go_quic_dispatcher);

  ~GoQuicSimpleDispatcher() override;

 protected:
  QuicServerSessionBase* CreateQuicSession(
      QuicConnectionId connection_id,
      const IPEndPoint& client_address) override;
};

}  // namespace net

#endif  // GO_QUIC_SIMPLE_DISPATCHER_H_
