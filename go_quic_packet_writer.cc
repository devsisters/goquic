#include "go_quic_packet_writer.h"

#include "net/quic/quic_types.h"

namespace net {

GoQuicPacketWriter::GoQuicPacketWriter(QuicClock *clock)
  : framer_(QuicSupportedVersions(), QuicTime::Zero(), true),
  last_packet_size_(0),
  write_blocked_(false),
  block_on_next_write_(false),
  is_write_blocked_data_buffered_(false),
  final_bytes_of_last_packet_(0),
  final_bytes_of_previous_packet_(0),
  use_tagging_decrypter_(false),
  packets_write_attempts_(0),
  clock_(clock) {
  }

WriteResult GoQuicPacketWriter::WritePacket(const char* buffer,
                                            size_t buf_len,
                                            const IPAddressNumber& self_address,
                                            const IPEndPoint& peer_address) {
  QuicEncryptedPacket packet(buffer, buf_len);
  ++packets_write_attempts_;

  if (packet.length() >= sizeof(final_bytes_of_last_packet_)) {
    final_bytes_of_previous_packet_ = final_bytes_of_last_packet_;
    memcpy(&final_bytes_of_last_packet_, packet.data() + packet.length() - 4,
           sizeof(final_bytes_of_last_packet_));
  }

//    if (use_tagging_decrypter_) {
//      framer_.SetDecrypter(new TaggingDecrypter, ENCRYPTION_NONE);
//    }
  EXPECT_TRUE(framer_.ProcessPacket(packet));
  if (block_on_next_write_) {
    write_blocked_ = true;
    block_on_next_write_ = false;
  }
  if (IsWriteBlocked()) {
    return WriteResult(WRITE_STATUS_BLOCKED, -1);
  }
  last_packet_size_ = packet.length();

  return WriteResult(WRITE_STATUS_OK, last_packet_size_);
}

}       // namespace net
