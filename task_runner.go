package goquic

// #include <stddef.h>
// #include "src/adaptor.h"
import "C"
import (
	"container/heap"
	"time"
)

type HeapItem struct {
	alarm *GoQuicAlarm

	// This duration should be managed explicitly by heap, and should not be shared with GoQuicAlarm to be thread-safe.
	deadline int64

	// Negative value means this alarm is not in heap, otherwise this alarm is idx-th element in heap.
	heapIdx int

	// Inserted order, to be used at tie-breaking
	insertOrd int
}

type AlarmHeap struct {
	items     []*HeapItem
	insertNum int
}

// This TaskRunner is NOT THREAD SAFE (and NEED NOT TO BE) so be careful
// All heap operations should be called in a mainloop, not seperated goroutine
type TaskRunner struct {
	alarmList map[*GoQuicAlarm]*HeapItem

	alarmHeap   *AlarmHeap
	deadlineTop int64
	timer       *time.Timer
}

func (ht *AlarmHeap) Len() int { return len(ht.items) }

func (ht *AlarmHeap) Less(i, j int) bool {
	if ht.items[i].deadline == ht.items[j].deadline {
		return ht.items[i].insertOrd < ht.items[j].insertOrd
	}
	return ht.items[i].deadline < ht.items[j].deadline
}

func (ht *AlarmHeap) Swap(i, j int) {
	ht.items[i], ht.items[j] = ht.items[j], ht.items[i]
	ht.items[i].heapIdx = i
	ht.items[j].heapIdx = j
}

func (ht *AlarmHeap) Push(x interface{}) {
	n := len(ht.items)
	item := x.(*HeapItem)
	item.heapIdx = n
	ht.insertNum += 1
	item.insertOrd = ht.insertNum
	ht.items = append(ht.items, item)
}

func (ht *AlarmHeap) Pop() interface{} {
	old := ht.items
	n := len(old)
	item := old[n-1]
	item.heapIdx = -1 // for safety
	ht.items = old[0 : n-1]
	return item
}

func newAlarmHeap() *AlarmHeap {
	return &AlarmHeap{make([]*HeapItem, 0), 0}
}

func CreateTaskRunner() *TaskRunner {
	taskRunner := &TaskRunner{
		alarmList: make(map[*GoQuicAlarm]*HeapItem),
		alarmHeap: newAlarmHeap(),
		timer:     time.NewTimer(time.Duration(200*365*24) * time.Hour), // ~ 200 year
	}

	return taskRunner
}

func (t *TaskRunner) RunAlarm(alarm *GoQuicAlarm) {
	item := t.alarmList[alarm]
	item.deadline = item.alarm.deadline
	if item.heapIdx < 0 {
		heap.Push(t.alarmHeap, item)
	} else {
		heap.Fix(t.alarmHeap, item.heapIdx)
	}
	if t.alarmHeap.Len() != 0 && t.deadlineTop != t.alarmHeap.items[0].deadline {
		t.resetTimer()
	}
}

func (t *TaskRunner) CancelAlarm(alarm *GoQuicAlarm) {
	item := t.alarmList[alarm]
	if item.heapIdx >= 0 {
		heap.Remove(t.alarmHeap, item.heapIdx)
	}
	if t.alarmHeap.Len() != 0 && t.deadlineTop != t.alarmHeap.items[0].deadline {
		t.resetTimer()
	}
}

func (t *TaskRunner) resetTimer() {
	if t.alarmHeap.Len() == 0 {
		return
	}

	t.deadlineTop = t.alarmHeap.items[0].deadline

	now := t.alarmHeap.items[0].alarm.Now()
	duration_i64 := t.alarmHeap.items[0].deadline - now
	if duration_i64 < 0 {
		duration_i64 = 0
	}
	// C++ clocks: Microseconds
	// Go duration: Nanoseconds
	duration := time.Duration(duration_i64) * time.Microsecond

	t.timer.Reset(duration)
}

func (t *TaskRunner) DoTasks() {
	if t.alarmHeap.Len() == 0 {
		return
	}
	now := t.alarmHeap.items[0].alarm.Now()

	taskItems := make([]*HeapItem, 0)

	for t.alarmHeap.Len() > 0 {
		duration_i64 := t.alarmHeap.items[0].deadline - now
		if duration_i64 < 0 {
			item := heap.Pop(t.alarmHeap).(*HeapItem)
			taskItems = append(taskItems, item)
		} else {
			//			fmt.Println(unsafe.Pointer(t), "next alarm will be called after", duration_i64)
			break
		}
	}

	for _, item := range taskItems {
		item.alarm.OnAlarm()
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
