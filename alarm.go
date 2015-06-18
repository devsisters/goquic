package goquic

// #include <stddef.h>
// #include "src/adaptor.h"
import "C"
import (
	"fmt"
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
}

func (alarm *GoQuicAlarm) SetImpl() {
	if alarm.isDestroyed {
		return
	}
	alarm.isCanceled = false
	alarm.taskRunner.RunAlarm(alarm)
}

// Called by C++ side when the C++ wrapper object is destoryed
func (alarm *GoQuicAlarm) Destroy() {
	alarm.isDestroyed = true
	alarm.CancelImpl()
	alarm.taskRunner.UnregisterAlarm(alarm)
}

func (alarm *GoQuicAlarm) CancelImpl() {
	alarm.isCanceled = true
	alarm.taskRunner.CancelAlarm(alarm)
}

func (alarm *GoQuicAlarm) OnAlarm() {
	if now := int64(C.clock_now(alarm.clock)); now < alarm.deadline {
		// This should be very rarely occrued. Otherwise this could be performance bottleneck.
		fmt.Println(now, time.Now().UnixNano()/1000000, alarm.wrapper, alarm.deadline, "Warning: Timer not adjustted")
		alarm.SetImpl()
		return
	}

	// There can be race condition between QuicAlarm destruction and OnAlarm callback. So this check is needed
	if alarm.isCanceled {
		return
	}

	C.go_quic_alarm_fire(alarm.wrapper)
}

func (alarm *GoQuicAlarm) Now() int64 {
	return int64(C.clock_now(alarm.clock))
}

//export CreateGoQuicAlarm
func CreateGoQuicAlarm(go_quic_alarm_go_wrapper_c unsafe.Pointer, clock_c unsafe.Pointer, task_runner_c unsafe.Pointer) unsafe.Pointer {
	alarm := &GoQuicAlarm{
		wrapper:    go_quic_alarm_go_wrapper_c,
		taskRunner: (*TaskRunner)(task_runner_c),
		clock:      clock_c,
		isCanceled: false,
	}
	alarm.taskRunner.RegisterAlarm(alarm)

	return unsafe.Pointer(alarm)
}

//export GoQuicAlarmSetImpl
func GoQuicAlarmSetImpl(alarm_c unsafe.Pointer, deadline int64) {
	alarm := (*GoQuicAlarm)(alarm_c)
	alarm.deadline = deadline
	alarm.SetImpl()
}

//export GoQuicAlarmCancelImpl
func GoQuicAlarmCancelImpl(alarm_c unsafe.Pointer) {
	alarm := (*GoQuicAlarm)(alarm_c)
	alarm.CancelImpl()
}

//export GoQuicAlarmDestroy
func GoQuicAlarmDestroy(alarm_c unsafe.Pointer) {
	alarm := (*GoQuicAlarm)(alarm_c)
	alarm.Destroy()
}
