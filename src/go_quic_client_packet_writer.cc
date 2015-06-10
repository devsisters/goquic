// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "go_quic_client_packet_writer.h"

#include "base/callback_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/sparse_histogram.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"

#include "go_functions.h"

namespace net {

GoQuicClientPacketWriter::GoQuicClientPacketWriter(void* go_udp_conn, void* go_task_runner)
    : go_udp_conn_(go_udp_conn),
      go_task_runner_(go_task_runner),
      write_blocked_(false) {
}

GoQuicClientPacketWriter::~GoQuicClientPacketWriter() {
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

WriteResult GoQuicClientPacketWriter::WritePacket(
    const char* buffer,
    size_t buf_len,
    const IPAddressNumber& self_address,
    const IPEndPoint& peer_address) {
  DCHECK(!IsWriteBlocked());
  int rv;
  if (buf_len <= static_cast<size_t>(std::numeric_limits<int>::max())) {
    WriteToUDPClient_C(go_udp_conn_, (void *)(&peer_address), (void *)buffer, buf_len, (void *)this, go_task_runner_);

    rv = buf_len;
  } else {
    rv = ERR_MSG_TOO_BIG;
  }
  WriteStatus status = WRITE_STATUS_OK;
  if (rv < 0) {
    if (rv != ERR_IO_PENDING) {
      UMA_HISTOGRAM_SPARSE_SLOWLY("Net.QuicSession.WriteError", -rv);
      status = WRITE_STATUS_ERROR;
    } else {
      status = WRITE_STATUS_BLOCKED;
      write_blocked_ = true;
    }
  }
  return WriteResult(status, rv);
}

}  // namespace net
