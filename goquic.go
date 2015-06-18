package goquic

// #cgo CXXFLAGS: -DUSE_OPENSSL=1 -std=gnu++11
// #cgo LDFLAGS: -pthread -lgoquic -lquic -lssl -lcrypto -lstdc++ -lm -lprotobuf
// #cgo darwin LDFLAGS: -framework CoreFoundation -framework Cocoa
// #include <stddef.h>
// #include "src/adaptor.h"
import "C"
import (
	"net"
	"unsafe"
)

func init() {
	// This initializes Chromium's base library codes
	C.initialize()
}

func SetLogLevel(level int) {
	C.set_log_level(C.int(level))
}

func writeToUDP(conn_c unsafe.Pointer, ip_endpoint_c unsafe.Pointer, buffer_c unsafe.Pointer, length_c C.size_t, isServer bool) {
	conn := (*net.UDPConn)(conn_c)
	endpoint := IPEndPoint{
		ipEndPoint: ip_endpoint_c,
	}
	peer_addr := endpoint.UDPAddr()

	buf := C.GoBytes(buffer_c, C.int(length_c))

	if isServer {
		conn.WriteToUDP(buf, peer_addr)
	} else {
		conn.Write(buf)
	}
}

//export WriteToUDP
func WriteToUDP(conn_c unsafe.Pointer, ip_endpoint_c unsafe.Pointer, buffer_c unsafe.Pointer, length_c C.size_t) {
	writeToUDP(conn_c, ip_endpoint_c, buffer_c, length_c, true)
}

//export WriteToUDPClient
func WriteToUDPClient(conn_c unsafe.Pointer, ip_endpoint_c unsafe.Pointer, buffer_c unsafe.Pointer, length_c C.size_t) {
	writeToUDP(conn_c, ip_endpoint_c, buffer_c, length_c, false)
}
