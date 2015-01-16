#include "go_quic_connection_helper.h"

#include "net/quic/quic_connection.h"
#include "net/quic/quic_clock.h"
#include "net/quic/crypto/quic_random.h"


namespace net {

class TestAlarm : public QuicAlarm {
  public:
    explicit TestAlarm(QuicAlarm::Delegate* delegate)
      : QuicAlarm(delegate) {
      }

    void SetImpl() override {}
    void CancelImpl() override {}
    using QuicAlarm::Fire;
};

const QuicClock* TestConnectionHelper::GetClock() const {
  return clock_;
}

QuicRandom* TestConnectionHelper::GetRandomGenerator() { return random_generator_; }

QuicAlarm* TestConnectionHelper::CreateAlarm(QuicAlarm::Delegate* delegate) {
  return new TestAlarm(delegate);
}

TestConnectionHelper::TestConnectionHelper(QuicClock* clock, QuicRandom* random_generator)
  : clock_(clock),
  random_generator_(random_generator) {
  }

}   // namespace net
