#ifndef GO_QUIC_CLIENT_PACKET_WRITER_H_
#define GO_QUIC_CLIENT_PACKET_WRITER_H_

#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/core/quic_packet_writer.h"
#include "go_structs.h"

namespace net {

struct WriteResult;

class GoQuicClientPacketWriter : public QuicPacketWriter {
 public:
  GoQuicClientPacketWriter(GoPtr go_writer);
  ~GoQuicClientPacketWriter() override;

  // QuicPacketWriter implementation:
  WriteResult WritePacket(const char* buffer,
                          size_t buf_len,
                          const IPAddress& self_address,
                          const IPEndPoint& peer_address,
                          PerPacketOptions* options) override;
  bool IsWriteBlockedDataBuffered() const override;
  bool IsWriteBlocked() const override;
  void SetWritable() override;
  QuicByteCount GetMaxPacketSize(const IPEndPoint& peer_address) const override;

 protected:
  void set_write_blocked(bool is_blocked) { write_blocked_ = is_blocked; }

 private:
  GoPtr go_writer_;

  // Whether a write is currently in flight.
  bool write_blocked_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicClientPacketWriter);
};

}  // namespace net

#endif  // GO_QUIC_CLIENT_PACKET_WRITER_H_
