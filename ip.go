package goquic

// #include <stddef.h>
// #include "adaptor.h"
import "C"
import (
	"net"
	"unsafe"
)

type IPAddressNumber struct {
	ipAddressNumber unsafe.Pointer
}

type IPEndPoint struct {
	ipEndPoint unsafe.Pointer
}

func CreateIPAddressNumber(ip net.IP) IPAddressNumber {
	ip4 := ip.To4()
	if ip4 != nil {
		ip = ip4
	}

	return IPAddressNumber{
		ipAddressNumber: (C.create_ip_address_number((*C.uchar)(unsafe.Pointer(&ip[0])), C.size_t(len(ip)))),
	}
}

func DeleteIPAddressNumber(ipAddr IPAddressNumber) {
	C.delete_ip_address_number(ipAddr.ipAddressNumber)
}

func CreateIPEndPointC(ipAddr IPAddressNumber, port uint16) IPEndPoint {
	return IPEndPoint{
		ipEndPoint: (C.create_ip_end_point(unsafe.Pointer(ipAddr.ipAddressNumber), C.uint16_t(port))),
	}
}

func CreateIPEndPoint(udpAddr *net.UDPAddr) IPEndPoint {
	ip_address_c := CreateIPAddressNumber(udpAddr.IP)
	defer DeleteIPAddressNumber(ip_address_c)
	return IPEndPoint{
		ipEndPoint: (C.create_ip_end_point(unsafe.Pointer(ip_address_c.ipAddressNumber), C.uint16_t(udpAddr.Port))),
	}
}

func (endpoint *IPEndPoint) UDPAddr() *net.UDPAddr {
	ip_buf := make([]byte, 16)
	ip_sz := C.ip_endpoint_ip_address(endpoint.ipEndPoint, unsafe.Pointer(&ip_buf[0]))
	port := int(C.ip_endpoint_port(endpoint.ipEndPoint))
	return &net.UDPAddr{
		IP:   net.IP(ip_buf[:int(ip_sz)]),
		Port: port,
	}
}

func DeleteIPEndPoint(endpoint IPEndPoint) {
	C.delete_ip_end_point(endpoint.ipEndPoint)
}
