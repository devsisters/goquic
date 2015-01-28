package goquic

// #cgo CXXFLAGS: -DUSE_OPENSSL=1 -std=gnu++11
// #cgo LDFLAGS: -pthread -lgoquic -lquic -lssl -lcrypto -lstdc++ -lm
// #cgo darwin LDFLAGS: -framework CoreFoundation -framework Cocoa
// #include <stddef.h>
// #include "adaptor.h"
import "C"
import (
	"net"
	"unsafe"
)

func Initialize() {
	C.initialize()
}

func SetLogLevel(level int) {
	C.set_log_level(C.int(level))
}

//export WriteToUDP
func WriteToUDP(conn_c unsafe.Pointer, ip_endpoint_c unsafe.Pointer, buffer_c unsafe.Pointer, length_c C.size_t, server_packet_writer_c unsafe.Pointer, task_runner_c unsafe.Pointer) {
	conn := (*net.UDPConn)(conn_c)
	endpoint := IPEndPoint{
		ipEndPoint: ip_endpoint_c,
	}
	peer_addr := endpoint.UDPAddr()

	bufOrig := C.GoBytes(buffer_c, C.int(length_c))
	buf := make([]byte, len(bufOrig))
	copy(buf, bufOrig) // XXX(hodduc) buffer copy?

	taskRunner := (*TaskRunner)(task_runner_c)

	go func() {
		conn.WriteToUDP(buf, peer_addr)
		taskRunner.CallWriteCallback(server_packet_writer_c, len(buf))
	}()
}
