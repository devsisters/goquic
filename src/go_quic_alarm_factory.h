#ifndef GO_QUIC_ALARM_FACTORY_H_
#define GO_QUIC_ALARM_FACTORY_H_

#include "go_structs.h"
#include "net/quic/core/quic_alarm.h"
#include "net/quic/core/quic_alarm_factory.h"
#include "net/quic/core/quic_clock.h"

namespace net {

class GoQuicAlarmFactory : public QuicAlarmFactory {
 public:
  explicit GoQuicAlarmFactory(QuicClock* clock, GoPtr task_runner);
  ~GoQuicAlarmFactory() override;

  // QuicAlarmFactory interface.
  QuicAlarm* CreateAlarm(QuicAlarm::Delegate* delegate) override;
  QuicArenaScopedPtr<QuicAlarm> CreateAlarm(
      QuicArenaScopedPtr<QuicAlarm::Delegate> delegate,
      QuicConnectionArena* arena) override;

 private:
  QuicClock* clock_;   // Not owned ( may be owned by connection helper )  TODO(hodduc): should ref-counted?
  GoPtr task_runner_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicAlarmFactory);
};

}  // namespace net

#endif  // GO_QUIC_ALARM_FACTORY_H_
