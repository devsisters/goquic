#include "net/quic/quic_clock.h"
#include "net/quic/quic_packet_writer.h"
#include "net/quic/quic_framer.h"
#include "net/quic/quic_types.h"
#include "net/base/net_util.h"

#define EXPECT_TRUE(x) { if (!(x)) printf("ERROR"); }

namespace net {

// ~= QuicServerPacketWriter

class GoQuicPacketWriter : public QuicPacketWriter {
 public:
  GoQuicPacketWriter(QuicClock *clock);

  // QuicPacketWriter interface
  WriteResult WritePacket(const char* buffer,
                          size_t buf_len,
                          const IPAddressNumber& self_address,
                          const IPEndPoint& peer_address) override;

  bool IsWriteBlockedDataBuffered() const override {
    return is_write_blocked_data_buffered_;
  }

  bool IsWriteBlocked() const override { return write_blocked_; }

  void SetWritable() override { write_blocked_ = false; }

  void BlockOnNextWrite() { block_on_next_write_ = true; }

  size_t last_packet_size() {
    return last_packet_size_;
  }

  void set_is_write_blocked_data_buffered(bool buffered) {
    is_write_blocked_data_buffered_ = buffered;
  }

  // final_bytes_of_last_packet_ returns the last four bytes of the previous
  // packet as a little-endian, uint32. This is intended to be used with a
  // TaggingEncrypter so that tests can determine which encrypter was used for
  // a given packet.
  uint32 final_bytes_of_last_packet() { return final_bytes_of_last_packet_; }

  // Returns the final bytes of the second to last packet.
  uint32 final_bytes_of_previous_packet() {
    return final_bytes_of_previous_packet_;
  }

  void use_tagging_decrypter() {
    use_tagging_decrypter_ = true;
  }

  uint32 packets_write_attempts() { return packets_write_attempts_; }

 private:
  QuicFramer framer_;
  size_t last_packet_size_;
  bool write_blocked_;
  bool block_on_next_write_;
  bool is_write_blocked_data_buffered_;
  uint32 final_bytes_of_last_packet_;
  uint32 final_bytes_of_previous_packet_;
  bool use_tagging_decrypter_;
  uint32 packets_write_attempts_;
  QuicClock *clock_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicPacketWriter);
};

}     // namespace net
