package goquic

// #include <stddef.h>
// #include "adaptor.h"
import "C"
import "unsafe"

type TaskRunner struct {
	AlarmChan chan *GoQuicAlarm
	WriteChan chan *WriteCallback
	alarmList []*GoQuicAlarm
}

type WriteCallback struct {
	rv                 int
	serverPacketWriter unsafe.Pointer
}

func (cb *WriteCallback) Callback() {
	C.packet_writer_on_write_complete(cb.serverPacketWriter, C.int(cb.rv))
}

func (t *TaskRunner) RunAlarm(alarm *GoQuicAlarm) {
	go func() {
		if alarm.timer == nil {
			return
		}

		select {
		//TODO (hodduc) alarm.timer.C will block infinitely if timer is resetted before deadline.
		case <-alarm.timer.C:
			if !alarm.isCanceled {
				t.AlarmChan <- alarm // To keep thread-safety, callback should be called in the main message loop, not in seperated goroutine.
			}
		}
	}()
}

func (t *TaskRunner) RegisterAlarm(alarm *GoQuicAlarm) {
	t.alarmList = append(t.alarmList, alarm)
}

func (t *TaskRunner) CallWriteCallback(server_packet_writer_c unsafe.Pointer, rv int) {
	t.WriteChan <- (&WriteCallback{
		rv:                 rv,
		serverPacketWriter: server_packet_writer_c,
	})
}
