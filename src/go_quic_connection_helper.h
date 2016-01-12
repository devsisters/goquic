#ifndef GO_QUIC_CONNECTION_HELPER_H_
#define GO_QUIC_CONNECTION_HELPER_H_
#include "net/quic/quic_connection.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_simple_buffer_allocator.h"

namespace net {

class QuicRandom;

namespace tools {

class GoQuicConnectionHelper : public QuicConnectionHelperInterface {
 public:
  GoQuicConnectionHelper(void* task_runner,
                         QuicClock* clock,
                         QuicRandom* random_generator);

  // QuicConnectionHelperInterface
  const QuicClock* GetClock() const override;
  QuicRandom* GetRandomGenerator() override;
  QuicAlarm* CreateAlarm(QuicAlarm::Delegate* delegate) override;
  QuicBufferAllocator* GetBufferAllocator() override;

 private:
  void* task_runner_;

  scoped_ptr<QuicClock> clock_;
  QuicRandom* random_generator_;
  SimpleBufferAllocator buffer_allocator_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicConnectionHelper);
};

}  // namespace tools
}  // namespace net

#endif  // GO_QUIC_CONNECTION_HELPER_H_
