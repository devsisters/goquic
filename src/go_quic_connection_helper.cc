#include "go_quic_connection_helper.h"
#include "go_quic_alarm_go_wrapper.h"

#include "net/quic/quic_connection.h"
#include "net/quic/quic_clock.h"
#include "net/quic/crypto/quic_random.h"

namespace net {

GoQuicConnectionHelper::GoQuicConnectionHelper(GoPtr task_runner,
                                               QuicClock* clock,
                                               QuicRandom* random_generator)
    : task_runner_(task_runner), random_generator_(random_generator) {
  clock_.reset(clock);
}

GoQuicConnectionHelper::~GoQuicConnectionHelper() {
  ReleaseTaskRunner_C(task_runner_);
}

const QuicClock* GoQuicConnectionHelper::GetClock() const {
  return clock_.get();
}

QuicRandom* GoQuicConnectionHelper::GetRandomGenerator() {
  return random_generator_;
}

QuicAlarm* GoQuicConnectionHelper::CreateAlarm(
    QuicAlarm::Delegate* delegate) {
  return new GoQuicAlarmGoWrapper(clock_.get(), task_runner_,
                                  QuicArenaScopedPtr<QuicAlarm::Delegate>(delegate));  // Should be deleted by caller
}

QuicArenaScopedPtr<QuicAlarm> GoQuicConnectionHelper::CreateAlarm(
    QuicArenaScopedPtr<QuicAlarm::Delegate> delegate,
    QuicConnectionArena* arena) {
  if (arena != nullptr) {
    return arena->New<GoQuicAlarmGoWrapper>(clock_.get(), task_runner_, std::move(delegate));
  } else {
    return QuicArenaScopedPtr<QuicAlarm>(
        new GoQuicAlarmGoWrapper(clock_.get(), task_runner_, std::move(delegate)));
  }
}

QuicBufferAllocator* GoQuicConnectionHelper::GetBufferAllocator() {
  return &buffer_allocator_;
}

}  // namespace net
