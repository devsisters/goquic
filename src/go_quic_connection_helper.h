#ifndef GO_QUIC_CONNECTION_HELPER_H__
#define GO_QUIC_CONNECTION_HELPER_H__
#include "net/quic/quic_connection.h"
#include "net/quic/quic_clock.h"
#include "net/quic/crypto/quic_random.h"

namespace net {
namespace tools {

// TODO(hodduc) rename TestConnectionHelper
class TestConnectionHelper : public QuicConnectionHelperInterface {
  public:
    TestConnectionHelper(void* task_runner, QuicClock* clock, QuicRandom* random_generator);

    // QuicConnectionHelperInterface
    const QuicClock* GetClock() const override;

    QuicRandom* GetRandomGenerator() override;

    QuicAlarm* CreateAlarm(QuicAlarm::Delegate* delegate) override;

  private:
    void* task_runner_;
    scoped_ptr<QuicClock> clock_;
    QuicRandom* random_generator_;
};

}   // namespace tools
}   // namespace net
#endif
