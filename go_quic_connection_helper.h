#include "net/quic/quic_connection.h"
#include "net/quic/quic_clock.h"
#include "net/quic/crypto/quic_random.h"

namespace net {

class TestConnectionHelper : public QuicConnectionHelperInterface {
  public:
    TestConnectionHelper(QuicClock* clock, QuicRandom* random_generator);

    // QuicConnectionHelperInterface
    const QuicClock* GetClock() const override;

    QuicRandom* GetRandomGenerator() override;

    QuicAlarm* CreateAlarm(QuicAlarm::Delegate* delegate) override;

  private:
    QuicClock* clock_;
    QuicRandom* random_generator_;
};

}   // namespace net
