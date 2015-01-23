#include "go_quic_connection_helper.h"
#include "go_quic_alarm_go_wrapper.h"

#include "net/quic/quic_connection.h"
#include "net/quic/quic_clock.h"
#include "net/quic/crypto/quic_random.h"


namespace net {

// TODO(hodduc) Rename TestConnectionHelper
const QuicClock* TestConnectionHelper::GetClock() const {
  return clock_;
}

QuicRandom* TestConnectionHelper::GetRandomGenerator() { return random_generator_; }

QuicAlarm* TestConnectionHelper::CreateAlarm(QuicAlarm::Delegate* delegate) {
  return new GoQuicAlarmGoWrapper(clock_, task_runner_, delegate);
}

TestConnectionHelper::TestConnectionHelper(void* task_runner, QuicClock* clock, QuicRandom* random_generator)
  : task_runner_(task_runner),
    clock_(clock),
    random_generator_(random_generator) {
  }

}   // namespace net
