package goquic

// #include <stddef.h>
// #include "adaptor.h"
import "C"
import (
	"time"
	"unsafe"
)

type GoQuicAlarm struct {
	deadline     int64
	isDestroyed  bool
	isCanceled   bool
	invalidateCh chan bool
	wrapper      unsafe.Pointer
	clock        unsafe.Pointer
	taskRunner   *TaskRunner
	timer        *time.Timer
}

func (alarm *GoQuicAlarm) SetImpl(now int64) {
	if alarm.isDestroyed {
		return
	}
	alarm.isCanceled = false

	duration_i64 := alarm.deadline - now
	if duration_i64 < 0 {
		duration_i64 = 0
	}

	if alarm.timer != nil {
		alarm.timer.Reset(time.Duration(duration_i64) * time.Microsecond)
		// If Reset fails (means OnAlarm already fired), SetImpl will called again automatically by OnAlarm() because alarm.deadline changed by caller. So no special handling is needed here.
	} else {
		alarm.timer = time.NewTimer(time.Duration(duration_i64) * time.Microsecond)
		alarm.taskRunner.RunAlarm(alarm)
	}
}

// Called by C++ side when the C++ wrapper object is destoryed
func (alarm *GoQuicAlarm) Destroy() {
	alarm.isDestroyed = true
	alarm.CancelImpl(0)
	alarm.taskRunner.UnregisterAlarm(alarm)
}

func (alarm *GoQuicAlarm) CancelImpl(now int64) {
	alarm.isCanceled = true

	if alarm.timer != nil {
		alarm.timer.Reset(0)
		alarm.timer = nil
	}
}

func (alarm *GoQuicAlarm) OnAlarm() {
	if now := int64(C.clock_now(alarm.clock)); now < alarm.deadline {
		alarm.SetImpl(now)
		return
	}

	// There can be race condition between QuicAlarm destruction and OnAlarm callback. So this check is needed
	if alarm.isCanceled {
		return
	}

	alarm.timer = nil
	C.go_quic_alarm_fire(alarm.wrapper)
}

//export CreateGoQuicAlarm
func CreateGoQuicAlarm(go_quic_alarm_go_wrapper_c unsafe.Pointer, clock_c unsafe.Pointer, task_runner_c unsafe.Pointer) unsafe.Pointer {
	alarm := &GoQuicAlarm{
		wrapper:    go_quic_alarm_go_wrapper_c,
		taskRunner: (*TaskRunner)(task_runner_c),
		clock:      clock_c,
		timer:      nil,
		isCanceled: false,
	}
	alarm.taskRunner.RegisterAlarm(alarm)

	return unsafe.Pointer(alarm)
}

//export GoQuicAlarmSetImpl
func GoQuicAlarmSetImpl(alarm_c unsafe.Pointer, deadline int64, now int64) {
	alarm := (*GoQuicAlarm)(alarm_c)
	alarm.deadline = deadline
	alarm.SetImpl(now)
}

//export GoQuicAlarmCancelImpl
func GoQuicAlarmCancelImpl(alarm_c unsafe.Pointer, now int64) {
	alarm := (*GoQuicAlarm)(alarm_c)
	alarm.CancelImpl(now)
}

//export GoQuicAlarmDestroy
func GoQuicAlarmDestroy(alarm_c unsafe.Pointer) {
	alarm := (*GoQuicAlarm)(alarm_c)
	alarm.Destroy()
}
