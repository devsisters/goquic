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

type UdpData struct {
	Addr *net.UDPAddr
	Buf  []byte
}

type ServerWriter struct {
	Ch chan UdpData
}

type ClientWriter struct {
	Ch chan UdpData
}

func NewServerWriter(ch chan UdpData) *ServerWriter {
	return &ServerWriter{ch}
}

func NewClientWriter(ch chan UdpData) *ClientWriter {
	return &ClientWriter{ch}
}

func writeToUDP(writer_c unsafe.Pointer, peer_ip unsafe.Pointer, peer_ip_sz C.size_t, peer_port uint16, buffer_c unsafe.Pointer, length_c C.size_t, isServer bool) {
	buf := C.GoBytes(buffer_c, C.int(length_c))

	if isServer {
		peer_addr := &net.UDPAddr{
			IP:   net.IP(C.GoBytes(peer_ip, C.int(peer_ip_sz))),
			Port: int(peer_port),
		}

		((*ServerWriter)(writer_c)).Ch <- UdpData{Buf: buf, Addr: peer_addr}
	} else {
		((*ClientWriter)(writer_c)).Ch <- UdpData{Buf: buf}
	}
}

//export WriteToUDP
func WriteToUDP(writer_c unsafe.Pointer, peer_ip unsafe.Pointer, peer_ip_sz C.size_t, peer_port uint16, buffer_c unsafe.Pointer, length_c C.size_t) {
	writeToUDP(writer_c, peer_ip, peer_ip_sz, peer_port, buffer_c, length_c, true)
}

//export WriteToUDPClient
func WriteToUDPClient(writer_c unsafe.Pointer, peer_ip unsafe.Pointer, peer_ip_sz C.size_t, peer_port uint16, buffer_c unsafe.Pointer, length_c C.size_t) {
	writeToUDP(writer_c, peer_ip, peer_ip_sz, peer_port, buffer_c, length_c, false)
}
