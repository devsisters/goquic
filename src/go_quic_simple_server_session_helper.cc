// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "go_quic_simple_server_session_helper.h"

namespace net {

GoQuicSimpleServerSessionHelper::GoQuicSimpleServerSessionHelper(QuicRandom* random)
    : random_(random) {}

GoQuicSimpleServerSessionHelper::~GoQuicSimpleServerSessionHelper() {}

QuicConnectionId GoQuicSimpleServerSessionHelper::GenerateConnectionIdForReject(
    QuicConnectionId /*connection_id*/) const {
  return random_->RandUint64();
}

bool GoQuicSimpleServerSessionHelper::CanAcceptClientHello(
    const CryptoHandshakeMessage& message,
    const IPEndPoint& self_address,
    std::string* error_details) const {
  return true;
}

}  // namespace net
