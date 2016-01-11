#include "go_quic_connection_helper.h"
#include "go_quic_alarm_go_wrapper.h"

#include "net/quic/quic_connection.h"
#include "net/quic/quic_clock.h"
#include "net/quic/crypto/quic_random.h"

namespace net {
namespace tools {

// TODO(hodduc) Rename TestConnectionHelper
const QuicClock* TestConnectionHelper::GetClock() const {
  return clock_.get();
}

QuicRandom* TestConnectionHelper::GetRandomGenerator() {
  return random_generator_;
}

QuicAlarm* TestConnectionHelper::CreateAlarm(QuicAlarm::Delegate* delegate) {
  return new GoQuicAlarmGoWrapper(clock_.get(), task_runner_,
                                  delegate);  // Should be deleted by caller
}

TestConnectionHelper::TestConnectionHelper(void* task_runner,
                                           QuicClock* clock,
                                           QuicRandom* random_generator)
    : task_runner_(task_runner), random_generator_(random_generator) {
  clock_.reset(clock);
}

}  // namespace tools
}  // namespace net
