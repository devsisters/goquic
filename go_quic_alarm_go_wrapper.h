#ifndef __GO_QUIC_ALARM_GO_WRAPPER_H__
#define __GO_QUIC_ALARM_GO_WRAPPER_H__
#include "go_functions.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_alarm.h"
#include "base/basictypes.h"

namespace net {

class GoQuicAlarmGoWrapper : public QuicAlarm {
  public:
    GoQuicAlarmGoWrapper(QuicClock* clock,
                         void* task_runner,
                         QuicAlarm::Delegate* delegate)
      : QuicAlarm(delegate),
        clock_(clock),
        go_quic_alarm_(CreateGoQuicAlarm_C(this, clock, task_runner)) {}

    // Should be called by gowrapper only
    void Fire_() {
      Fire();
    }

    void SetGoQuicAlarm(void *go_quic_alarm) {
      go_quic_alarm_ = go_quic_alarm;
    }

  protected:
    void SetImpl() override {
      GoQuicAlarmSetImpl_C(go_quic_alarm_, quic_clock_to_int64(deadline()), quic_clock_to_int64(clock_->Now()));
    }
    void CancelImpl() override {
      GoQuicAlarmCancelImpl_C(go_quic_alarm_, quic_clock_to_int64(clock_->Now()));
    }

  private:
    QuicClock* clock_;
    void* go_quic_alarm_;

    int64_t quic_clock_to_int64(QuicTime time) {
      return time.Subtract(QuicTime::Zero()).ToMicroseconds();
    }
};

}
#endif
