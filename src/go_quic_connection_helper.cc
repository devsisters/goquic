#include "go_quic_connection_helper.h"

#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_clock.h"
#include "net/quic/core/crypto/quic_random.h"

namespace net {

GoQuicConnectionHelper::GoQuicConnectionHelper(QuicClock* clock,
                                               QuicRandom* random_generator)
    : random_generator_(random_generator) {
  clock_.reset(clock);
}

GoQuicConnectionHelper::~GoQuicConnectionHelper() {}

const QuicClock* GoQuicConnectionHelper::GetClock() const {
  return clock_.get();
}

QuicRandom* GoQuicConnectionHelper::GetRandomGenerator() {
  return random_generator_;
}

QuicBufferAllocator* GoQuicConnectionHelper::GetBufferAllocator() {
  return &buffer_allocator_;
}

}  // namespace net
