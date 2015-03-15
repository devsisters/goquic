package goquic

// #include <stddef.h>
// #include "adaptor.h"
import "C"
import (
	"container/heap"
	"time"
	"unsafe"
)

type HeapItem struct {
	alarm *GoQuicAlarm

	// This duration should be managed explicitly by heap, and should not be shared with GoQuicAlarm to be thread-safe.
	deadline int64

	// Negative value means this alarm is not in heap, otherwise this alarm is idx-th element in heap.
	heapIdx int
}

type AlarmHeap []*HeapItem

// This TaskRunner is NOT THREAD SAFE (and NEED NOT TO BE) so be careful
// All heap operations and callback operations should be called in a mainloop, not seperated goroutine
type TaskRunner struct {
	WriteChan chan *WriteCallback
	alarmList map[*GoQuicAlarm]*HeapItem

	alarmHeap   AlarmHeap
	deadlineTop int64
	timer       *time.Timer
}

func (ht AlarmHeap) Len() int { return len(ht) }

func (ht AlarmHeap) Less(i, j int) bool {
	return ht[i].deadline < ht[j].deadline
}

func (ht AlarmHeap) Swap(i, j int) {
	ht[i], ht[j] = ht[j], ht[i]
	ht[i].heapIdx = i
	ht[j].heapIdx = j
}

func (ht *AlarmHeap) Push(x interface{}) {
	n := len(*ht)
	item := x.(*HeapItem)
	item.heapIdx = n
	*ht = append(*ht, item)
}

func (ht *AlarmHeap) Pop() interface{} {
	old := *ht
	n := len(old)
	item := old[n-1]
	item.heapIdx = -1 // for safety
	*ht = old[0 : n-1]
	return item
}

type WriteCallback struct {
	rv                 int
	serverPacketWriter unsafe.Pointer
}

func (cb *WriteCallback) Callback() {
	C.packet_writer_on_write_complete(cb.serverPacketWriter, C.int(cb.rv))
}

func CreateTaskRunner(writeCh chan *WriteCallback) *TaskRunner {
	taskRunner := &TaskRunner{
		WriteChan: writeCh,
		alarmList: make(map[*GoQuicAlarm]*HeapItem),
		alarmHeap: make(AlarmHeap, 0),
		timer:     time.NewTimer(time.Duration(200*365*24) * time.Hour), // ~ 200 year
	}

	return taskRunner
}

func (t *TaskRunner) RunAlarm(alarm *GoQuicAlarm) {
	item := t.alarmList[alarm]
	item.deadline = item.alarm.deadline
	if item.heapIdx < 0 {
		heap.Push(&t.alarmHeap, item)
	} else {
		heap.Fix(&t.alarmHeap, item.heapIdx)
	}
	t.resetTimer()
}

func (t *TaskRunner) CancelAlarm(alarm *GoQuicAlarm) {
	item := t.alarmList[alarm]
	if item.heapIdx >= 0 {
		heap.Remove(&t.alarmHeap, item.heapIdx)
	}
	t.resetTimer()
}

func (t *TaskRunner) resetTimer() {
	if t.alarmHeap.Len() == 0 {
		return
	}

	if t.deadlineTop == t.alarmHeap[0].deadline {
		return
	} else {
		t.deadlineTop = t.alarmHeap[0].deadline
	}

	now := t.alarmHeap[0].alarm.Now()
	duration_i64 := t.alarmHeap[0].deadline - now
	if duration_i64 < 0 {
		duration_i64 = 0
	}
	// C++ clocks: Microseconds
	// Go duration: Nanoseconds
	duration := time.Duration(duration_i64) * time.Microsecond

	if t.timer == nil {
		t.timer = time.NewTimer(duration)
	} else {
		t.timer.Reset(duration)
	}
}

func (t *TaskRunner) DoTasks() {
	if t.alarmHeap.Len() == 0 {
		return
	}
	now := t.alarmHeap[0].alarm.Now()
	for t.alarmHeap.Len() > 0 {
		duration_i64 := t.alarmHeap[0].deadline - now
		if duration_i64 < 0 {
			item := heap.Pop(&t.alarmHeap).(*HeapItem)
			item.alarm.OnAlarm()
		} else {
			//			fmt.Println(unsafe.Pointer(t), "next alarm will be called after", duration_i64)
			break
		}
	}
	t.resetTimer()

}

func (t *TaskRunner) WaitTimer() <-chan time.Time {
	return t.timer.C
}

func (t *TaskRunner) RegisterAlarm(alarm *GoQuicAlarm) {
	// This is to prevent garbage collection. This is cleaned up on UnregisterAlarm()
	t.alarmList[alarm] = &HeapItem{
		alarm:   alarm,
		heapIdx: -1,
	}
}

func (t *TaskRunner) UnregisterAlarm(alarm *GoQuicAlarm) {
	if t.alarmList[alarm].heapIdx != -1 {
		t.CancelAlarm(alarm)
	}
	delete(t.alarmList, alarm)
}

func (t *TaskRunner) CallWriteCallback(server_packet_writer_c unsafe.Pointer, rv int) {
	t.WriteChan <- (&WriteCallback{
		rv:                 rv,
		serverPacketWriter: server_packet_writer_c,
	})
}
