package goquic

// #include <stddef.h>
// #include "src/adaptor.h"
import "C"
import "net"

type GoIPEndPoint struct {
	packed []byte
	port   int
}

func CreateIPEndPoint(udpAddr *net.UDPAddr) *GoIPEndPoint {
	// Note: string(ip) != ip.String()
	//       4 byte     vs human-readable repr

	ip := udpAddr.IP.To4()
	if ip == nil {
		ip = udpAddr.IP
	}

	return &GoIPEndPoint{packed: []byte(ip), port: udpAddr.Port}
}
