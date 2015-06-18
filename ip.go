package goquic

// #include <stddef.h>
// #include "src/adaptor.h"
import "C"
import (
	"net"
	"unsafe"
)

func CreateIPEndPointPacked(udpAddr *net.UDPAddr) *C.struct_GoIPEndPoint {
	ip := udpAddr.IP.To4()
	if ip == nil {
		ip = udpAddr.IP
	}

	return &C.struct_GoIPEndPoint{
		ip_buf:    (*C.uchar)(unsafe.Pointer(&ip[0])),
		ip_length: C.size_t(len(ip)),
		port:      C.uint16_t(udpAddr.Port),
	}
}
