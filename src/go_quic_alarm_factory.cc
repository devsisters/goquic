#include "go_quic_alarm_factory.h"
#include "go_quic_alarm_go_wrapper.h"

namespace net {

GoQuicAlarmFactory::GoQuicAlarmFactory(QuicClock* clock, GoPtr task_runner)
    : clock_(clock), 
      task_runner_(task_runner) {}
GoQuicAlarmFactory::~GoQuicAlarmFactory() {
  ReleaseTaskRunner_C(task_runner_);
}

QuicAlarm* GoQuicAlarmFactory::CreateAlarm(
    QuicAlarm::Delegate* delegate) {
  return new GoQuicAlarmGoWrapper(clock_, task_runner_,
                                  QuicArenaScopedPtr<QuicAlarm::Delegate>(delegate));  // Should be deleted by caller
}

QuicArenaScopedPtr<QuicAlarm> GoQuicAlarmFactory::CreateAlarm(
    QuicArenaScopedPtr<QuicAlarm::Delegate> delegate,
    QuicConnectionArena* arena) {
  if (arena != nullptr) {
    return arena->New<GoQuicAlarmGoWrapper>(clock_, task_runner_, std::move(delegate));
  } else {
    return QuicArenaScopedPtr<QuicAlarm>(
        new GoQuicAlarmGoWrapper(clock_, task_runner_, std::move(delegate)));
  }
}

}
