// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "go_quic_simple_crypto_server_stream_helper.h"

namespace net {

GoQuicSimpleCryptoServerStreamHelper::GoQuicSimpleCryptoServerStreamHelper(
    QuicRandom* random)
    : random_(random) {}

GoQuicSimpleCryptoServerStreamHelper::~GoQuicSimpleCryptoServerStreamHelper() {}

QuicConnectionId
    GoQuicSimpleCryptoServerStreamHelper::GenerateConnectionIdForReject(
        QuicConnectionId /*connection_id*/) const {
  return random_->RandUint64();
}

bool GoQuicSimpleCryptoServerStreamHelper::CanAcceptClientHello(
    const CryptoHandshakeMessage& message,
    const IPEndPoint& self_address,
    std::string* error_details) const {
  return true;
}

}  // namespace net
