// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef GO_QUIC_SERVER_PACKET_WRITER_H_
#define GO_QUIC_SERVER_PACKET_WRITER_H_

#include "base/memory/weak_ptr.h"
#include "base/callback.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_packet_writer.h"
#include "net/quic/core/quic_protocol.h"
#include "go_structs.h"

namespace net {

class QuicBlockedWriterInterface;
struct WriteResult;

class GoQuicServerPacketWriter : public QuicPacketWriter {
 public:
  typedef base::Callback<void(WriteResult)> WriteCallback;

  GoQuicServerPacketWriter(GoPtr go_writer,
                           QuicBlockedWriterInterface* blocked_writer);
  ~GoQuicServerPacketWriter() override;

  // Wraps WritePacket, and ensures that |callback| is run on successful write.
  WriteResult WritePacketWithCallback(const char* buffer,
                                      size_t buf_len,
                                      const IPAddress& self_address,
                                      const IPEndPoint& peer_address,
                                      PerPacketOptions* options,
                                      WriteCallback callback);

  WriteResult WritePacket(const char* buffer,
                          size_t buf_len,
                          const IPAddress& self_address,
                          const IPEndPoint& peer_address,
                          PerPacketOptions* options) override;

  void OnWriteComplete(int rv);

  // QuicPacketWriter implementation:
  bool IsWriteBlockedDataBuffered() const override;
  bool IsWriteBlocked() const override;
  void SetWritable() override;
  QuicByteCount GetMaxPacketSize(const IPEndPoint& peer_address) const override;

 private:
  GoPtr go_writer_;

  // To be notified after every successful asynchronous write.
  QuicBlockedWriterInterface* blocked_writer_;

  // To call once the write completes.
  WriteCallback callback_;

  // Whether a write is currently in flight.
  bool write_blocked_;

  base::WeakPtrFactory<GoQuicServerPacketWriter> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicServerPacketWriter);
};

}  // namespace net

#endif  // GO_QUIC_SERVER_PACKET_WRITER_H_
