#ifndef NET_QUIC_QUIC_CLIENT_PACKET_WRITER_H_
#define NET_QUIC_QUIC_CLIENT_PACKET_WRITER_H_

#include "base/basictypes.h"
#include "base/memory/weak_ptr.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_packet_writer.h"
#include "net/quic/quic_protocol.h"

namespace net {

struct WriteResult;

class GoQuicClientPacketWriter : public QuicPacketWriter {
 public:
  GoQuicClientPacketWriter(void *go_writer);
  ~GoQuicClientPacketWriter() override;

  // QuicPacketWriter implementation:
  bool IsWriteBlockedDataBuffered() const override;
  bool IsWriteBlocked() const override;
  void SetWritable() override;

 protected:
  WriteResult WritePacket(const char* buffer,
                          size_t buf_len,
                          const IPAddressNumber& self_address,
                          const IPEndPoint& peer_address) override;

 private:
  void* go_writer_;

  // Whether a write is currently in flight.
  bool write_blocked_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicClientPacketWriter);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_CLIENT_PACKET_WRITER_H_
