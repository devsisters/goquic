#ifndef GO_QUIC_CONNECTION_HELPER_H_
#define GO_QUIC_CONNECTION_HELPER_H_
#include "net/quic/quic_connection.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_simple_buffer_allocator.h"
#include "go_structs.h"

namespace net {

class QuicRandom;

using QuicStreamBufferAllocator = SimpleBufferAllocator;

class GoQuicConnectionHelper : public QuicConnectionHelperInterface {
 public:
  GoQuicConnectionHelper(GoPtr task_runner,
                         QuicClock* clock,
                         QuicRandom* random_generator);
  ~GoQuicConnectionHelper() override;

  // QuicConnectionHelperInterface
  const QuicClock* GetClock() const override;
  QuicRandom* GetRandomGenerator() override;
  QuicAlarm* CreateAlarm(QuicAlarm::Delegate* delegate) override;
  QuicArenaScopedPtr<QuicAlarm> CreateAlarm(
    QuicArenaScopedPtr<QuicAlarm::Delegate> delegate,
    QuicConnectionArena* arena) override;

  QuicBufferAllocator* GetBufferAllocator() override;

 private:
  GoPtr task_runner_;

  scoped_ptr<QuicClock> clock_;
  QuicRandom* random_generator_;
  QuicStreamBufferAllocator buffer_allocator_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicConnectionHelper);
};

}  // namespace net

#endif  // GO_QUIC_CONNECTION_HELPER_H_
