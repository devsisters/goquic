#ifndef __GO_QUIC_ALARM_GO_WRAPPER_H__
#define __GO_QUIC_ALARM_GO_WRAPPER_H__
#include "go_functions.h"
#include "net/quic/core/quic_clock.h"
#include "net/quic/core/quic_alarm.h"
#include "base/logging.h"
#include <iostream>

namespace net {

class GoQuicAlarmGoWrapper : public QuicAlarm {
 public:
  GoQuicAlarmGoWrapper(QuicClock* clock,
                       GoPtr task_runner,
                       QuicArenaScopedPtr<Delegate> delegate)
      : QuicAlarm(std::move(delegate)),
        go_quic_alarm_(CreateGoQuicAlarm_C(this, clock, task_runner)) {}

  virtual ~GoQuicAlarmGoWrapper() {
    // Notify go object that we are destroyed
    GoQuicAlarmDestroy_C(go_quic_alarm_);
  }

  // Should be called by gowrapper only
  void Fire_() { Fire(); }

  void SetGoQuicAlarm(GoPtr go_quic_alarm) { go_quic_alarm_ = go_quic_alarm; }

 protected:
  void SetImpl() override {
    GoQuicAlarmSetImpl_C(go_quic_alarm_, quic_clock_to_int64(deadline()));
  }
  void CancelImpl() override { GoQuicAlarmCancelImpl_C(go_quic_alarm_); }

 private:
  GoPtr go_quic_alarm_;

  int64_t quic_clock_to_int64(QuicTime time) {
    return (time - QuicTime::Zero()).ToMicroseconds();
  }
};
}
#endif
