// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "go_quic_client_packet_writer.h"

#include "net/base/net_errors.h"
#include "go_functions.h"

namespace net {

GoQuicClientPacketWriter::GoQuicClientPacketWriter(GoPtr go_writer)
    : go_writer_(go_writer), write_blocked_(false) {}

GoQuicClientPacketWriter::~GoQuicClientPacketWriter() {
  ReleaseClientWriter_C(go_writer_);
}

WriteResult GoQuicClientPacketWriter::WritePacket(
    const char* buffer,
    size_t buf_len,
    const IPAddress& self_address,
    const IPEndPoint& peer_address,
    PerPacketOptions* /*options*/) {
  DCHECK(!IsWriteBlocked());
  int rv;
  if (buf_len <= static_cast<size_t>(std::numeric_limits<int>::max())) {
    auto peer_ip = peer_address.address().bytes();
    WriteToUDPClient_C(go_writer_, reinterpret_cast<char*>(peer_ip.data()), peer_ip.size(),
                       peer_address.port(), (void*)buffer, buf_len);

    rv = buf_len;
  } else {
    rv = ERR_MSG_TOO_BIG;
  }
  WriteStatus status = WRITE_STATUS_OK;
  if (rv < 0) {
    if (rv != ERR_IO_PENDING) {
      status = WRITE_STATUS_ERROR;
    } else {
      status = WRITE_STATUS_BLOCKED;
      write_blocked_ = true;
    }
  }
  return WriteResult(status, rv);
}

bool GoQuicClientPacketWriter::IsWriteBlockedDataBuffered() const {
  return false;
}

bool GoQuicClientPacketWriter::IsWriteBlocked() const {
  return write_blocked_;
}

void GoQuicClientPacketWriter::SetWritable() {
  write_blocked_ = false;
}

QuicByteCount GoQuicClientPacketWriter::GetMaxPacketSize(
    const IPEndPoint& peer_address) const {
  return kMaxPacketSize;
}

}  // namespace net
