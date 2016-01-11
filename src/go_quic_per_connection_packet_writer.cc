// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "go_quic_per_connection_packet_writer.h"

#include "base/bind.h"
#include "go_quic_server_packet_writer.h"

namespace net {
namespace tools {

GoQuicPerConnectionPacketWriter::GoQuicPerConnectionPacketWriter(
    GoQuicServerPacketWriter* shared_writer,
    QuicConnection* connection)
    : shared_writer_(shared_writer),
      connection_(connection),
      weak_factory_(this) {}

GoQuicPerConnectionPacketWriter::~GoQuicPerConnectionPacketWriter() {}

QuicPacketWriter* GoQuicPerConnectionPacketWriter::shared_writer() const {
  return shared_writer_;
}

WriteResult GoQuicPerConnectionPacketWriter::WritePacket(
    const char* buffer,
    size_t buf_len,
    const IPAddressNumber& self_address,
    const IPEndPoint& peer_address) {
  return shared_writer_->WritePacketWithCallback(
      buffer, buf_len, self_address, peer_address,
      base::Bind(&GoQuicPerConnectionPacketWriter::OnWriteComplete,
                 weak_factory_.GetWeakPtr()));
}

bool GoQuicPerConnectionPacketWriter::IsWriteBlockedDataBuffered() const {
  return shared_writer_->IsWriteBlockedDataBuffered();
}

bool GoQuicPerConnectionPacketWriter::IsWriteBlocked() const {
  return shared_writer_->IsWriteBlocked();
}

void GoQuicPerConnectionPacketWriter::SetWritable() {
  shared_writer_->SetWritable();
}

void GoQuicPerConnectionPacketWriter::OnWriteComplete(WriteResult result) {
  if (connection_ && result.status == WRITE_STATUS_ERROR) {
    connection_->OnWriteError(result.error_code);
  }
}

QuicByteCount GoQuicPerConnectionPacketWriter::GetMaxPacketSize(
    const IPEndPoint& peer_address) const {
  return shared_writer_->GetMaxPacketSize(peer_address);
}

}  // namespace tools
}  // namespace net
