package goquic

// #include <stddef.h>
// #include "src/adaptor.h"
import "C"
import (
	"net"
	"unsafe"
)

type UdpData struct {
	Addr *net.UDPAddr
	Buf  []byte
	N    int
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

func writeToUDP(go_writer_key int64, peer_ip unsafe.Pointer, peer_ip_sz C.size_t, peer_port uint16, buffer_c unsafe.Pointer, length_c C.size_t, isServer bool) {
	buf := C.GoBytes(buffer_c, C.int(length_c))

	if isServer {
		peer_addr := &net.UDPAddr{
			IP:   net.IP(C.GoBytes(peer_ip, C.int(peer_ip_sz))),
			Port: int(peer_port),
		}

		serverWriterPtr.Get(go_writer_key).Ch <- UdpData{Buf: buf, Addr: peer_addr, N: int(length_c)}
	} else {
		clientWriterPtr.Get(go_writer_key).Ch <- UdpData{Buf: buf, N: int(length_c)}
	}
}

//export WriteToUDP
func WriteToUDP(go_writer_key int64, peer_ip unsafe.Pointer, peer_ip_sz C.size_t, peer_port uint16, buffer_c unsafe.Pointer, length_c C.size_t) {
	writeToUDP(go_writer_key, peer_ip, peer_ip_sz, peer_port, buffer_c, length_c, true)
}

//export WriteToUDPClient
func WriteToUDPClient(go_writer_key int64, peer_ip unsafe.Pointer, peer_ip_sz C.size_t, peer_port uint16, buffer_c unsafe.Pointer, length_c C.size_t) {
	writeToUDP(go_writer_key, peer_ip, peer_ip_sz, peer_port, buffer_c, length_c, false)
}

//export ReleaseClientWriter
func ReleaseClientWriter(go_client_writer_key int64) {
	clientWriterPtr.Del(go_client_writer_key)
}

//export ReleaseServerWriter
func ReleaseServerWriter(go_server_writer_key int64) {
	serverWriterPtr.Del(go_server_writer_key)
}
