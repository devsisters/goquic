// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef GO_QUIC_PER_CONNECTION_PACKET_WRITER_H_
#define GO_QUIC_PER_CONNECTION_PACKET_WRITER_H_

#include "base/memory/weak_ptr.h"
#include "net/base/ip_address.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_packet_writer.h"

namespace net {

class GoQuicServerPacketWriter;

// A connection-specific packet writer that notifies its connection when its
// writes to the shared GoQuicServerPacketWriter complete.
// This class is necessary because multiple connections can share the same
// GoQuicServerPacketWriter, so it has no way to know which connection to
// notify.
class GoQuicPerConnectionPacketWriter : public QuicPacketWriter {
 public:
  // Does not take ownership of |shared_writer| or |connection|.
  GoQuicPerConnectionPacketWriter(GoQuicServerPacketWriter* shared_writer);
  ~GoQuicPerConnectionPacketWriter() override;

  QuicPacketWriter* shared_writer() const;
  void set_connection(QuicConnection* connection) { connection_ = connection; }
  QuicConnection* connection() const { return connection_; }

  // Default implementation of the QuicPacketWriter interface: Passes everything
  // to |shared_writer_|.
  WriteResult WritePacket(const char* buffer,
                          size_t buf_len,
                          const IPAddress& self_address,
                          const IPEndPoint& peer_address,
                          PerPacketOptions* options) override;
  bool IsWriteBlockedDataBuffered() const override;
  bool IsWriteBlocked() const override;
  void SetWritable() override;
  QuicByteCount GetMaxPacketSize(const IPEndPoint& peer_address) const override;

 private:
  void OnWriteComplete(WriteResult result);

  GoQuicServerPacketWriter* shared_writer_;  // Not owned.
  QuicConnection* connection_;               // Not owned.

  base::WeakPtrFactory<GoQuicPerConnectionPacketWriter> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicPerConnectionPacketWriter);
};

}  // namespace net

#endif  // GO_QUIC_PER_CONNECTION_PACKET_WRITER_H_
