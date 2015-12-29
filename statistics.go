package goquic

// #include <stddef.h>
// #include "src/go_structs.h"
import "C"

type ServerStatistics struct {
	SessionStatistics []SessionStatistics
}

type DispatcherStatistics struct {
	SessionStatistics []SessionStatistics
}

type SessionStatistics struct {
	Cstat C.struct_ConnStat
}

type statCallback chan DispatcherStatistics
