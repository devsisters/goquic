// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "go_quic_server_packet_writer.h"

#include "base/callback_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/sparse_histogram.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"

#include "go_functions.h"

namespace net {

GoQuicServerPacketWriter::GoQuicServerPacketWriter(
    GoPtr go_writer,
    QuicBlockedWriterInterface* blocked_writer)
    : go_writer_(go_writer),
      blocked_writer_(blocked_writer),
      write_blocked_(false),
      weak_factory_(this) {}

GoQuicServerPacketWriter::~GoQuicServerPacketWriter() {
  ReleaseServerWriter_C(go_writer_);
	// TODO(hodduc): release go_writer
}

WriteResult GoQuicServerPacketWriter::WritePacketWithCallback(
    const char* buffer,
    size_t buf_len,
    const IPAddress& self_address,
    const IPEndPoint& peer_address,
    PerPacketOptions* options,
    WriteCallback callback) {
  DCHECK(callback_.is_null());
  callback_ = callback;
  WriteResult result =
      WritePacket(buffer, buf_len, self_address, peer_address, options);
  if (result.status != WRITE_STATUS_BLOCKED) {
    callback_.Reset();
  }
  return result;
}

void GoQuicServerPacketWriter::OnWriteComplete(int rv) {
  DCHECK_NE(rv, ERR_IO_PENDING);
  write_blocked_ = false;
  WriteResult result(rv < 0 ? WRITE_STATUS_ERROR : WRITE_STATUS_OK, rv);
  if (!callback_.is_null()) {
    base::ResetAndReturn(&callback_).Run(result);
  }
  blocked_writer_->OnCanWrite();
}

bool GoQuicServerPacketWriter::IsWriteBlockedDataBuffered() const {
  // UDPServerSocket::SendTo buffers the data until the Write is permitted.
  return true;
}

bool GoQuicServerPacketWriter::IsWriteBlocked() const {
  return write_blocked_;
}

void GoQuicServerPacketWriter::SetWritable() {
  write_blocked_ = false;
}

WriteResult GoQuicServerPacketWriter::WritePacket(
    const char* buffer,
    size_t buf_len,
    const IPAddress& self_address,
    const IPEndPoint& peer_address,
    PerPacketOptions* options) {
  //  scoped_refptr<StringIOBuffer> buf(
  //      new StringIOBuffer(std::string(buffer, buf_len)));
  DCHECK(!IsWriteBlocked());
  int rv;
  if (buf_len <= static_cast<size_t>(std::numeric_limits<int>::max())) {
    auto peer_ip = peer_address.address().bytes();

    WriteToUDP_C(go_writer_, reinterpret_cast<char*>(peer_ip.data()), peer_ip.size(),
                 peer_address.port(), (void*)buffer, buf_len);
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

QuicByteCount GoQuicServerPacketWriter::GetMaxPacketSize(
    const IPEndPoint& peer_address) const {
  return kMaxPacketSize;
}

}  // namespace net
