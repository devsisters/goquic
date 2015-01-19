package main

// #cgo CXXFLAGS: -DUSE_OPENSSL=1 -Iquic_test/src/ -std=gnu++11
// #cgo LDFLAGS: -pthread -Lquic_test/boringssl/build/crypto -Lquic_test/boringssl/build/ssl quic_test/build/libquic.a -lssl -lcrypto -lz
// #include <stddef.h>
// #include "adaptor.h"
import "C"
import "fmt"
import "unsafe"
import "net"

type QuicConnection struct {
	quic_connection unsafe.Pointer
}

type QuicEncryptedPacket struct {
	encrypted_packet unsafe.Pointer
}

type QuicDispatcher struct {
	quic_dispatcher unsafe.Pointer
}

type IPAddressNumber struct {
	ip_address_number unsafe.Pointer
}

type IPEndPoint struct {
	ip_end_point unsafe.Pointer
}

/*
func CreateQuicConnection(connection_id int, ip_addr net.IP) QuicConnection {
	ip := CreateIPAddressNumber(ip_addr)
	defer DeleteIPAddressNumber(ip)
	ip_endpoint := CreateIPEndPointC(ip, 80)
	defer DeleteIPEndPoint(ip_endpoint)
	ptr := C.create_quic_connection(C.int(connection_id), unsafe.Pointer(ip_endpoint.ip_end_point))

	return QuicConnection{quic_connection: ptr}
}

func (c *QuicConnection) Version() int {
	ver := C.quic_connection_version(c.quic_connection)
	return int(ver)
}

func (c *QuicConnection) ProcessUdpPacket(self_address *net.UDPAddr, peer_address *net.UDPAddr, buffer []byte) {
	packet := CreateQuicEncryptedPacket(buffer)
	defer DeleteQuicEncryptedPacket(packet)
	self_address_c := CreateIPEndPoint(self_address)
	defer DeleteIPEndPoint(self_address_c)
	peer_address_c := CreateIPEndPoint(peer_address)
	defer DeleteIPEndPoint(peer_address_c)
	C.quic_connection_process_udp_packet(c.quic_connection, self_address_c.ip_end_point, peer_address_c.ip_end_point, packet.encrypted_packet)
}
*/

// Note that the buffer is NOT copied. So it is the callers responsibility to retain the buffer until it is processed by QuicConnection
func CreateQuicEncryptedPacket(buffer []byte) QuicEncryptedPacket {
	return QuicEncryptedPacket{
		encrypted_packet: C.create_quic_encrypted_packet((*C.char)(unsafe.Pointer(&buffer[0])), C.size_t(len(buffer))),
	}
}

func DeleteQuicEncryptedPacket(packet QuicEncryptedPacket) {
	C.delete_quic_encrypted_packet(packet.encrypted_packet)
}

func CreateIPAddressNumber(ip net.IP) IPAddressNumber {
	return IPAddressNumber{
		ip_address_number: (C.create_ip_address_number((*C.uchar)(unsafe.Pointer(&ip[0])), C.size_t(len(ip)))),
	}
}

func DeleteIPAddressNumber(ip_address IPAddressNumber) {
	C.delete_ip_address_number(ip_address.ip_address_number)
}

func CreateIPEndPointC(ip_address IPAddressNumber, port uint16) IPEndPoint {
	return IPEndPoint{
		ip_end_point: (C.create_ip_end_point(unsafe.Pointer(ip_address.ip_address_number), C.uint16_t(port))),
	}
}

func CreateIPEndPoint(ip_endpoint *net.UDPAddr) IPEndPoint {
	ip_address_c := CreateIPAddressNumber(ip_endpoint.IP)
	defer DeleteIPAddressNumber(ip_address_c)
	return IPEndPoint{
		ip_end_point: (C.create_ip_end_point(unsafe.Pointer(ip_address_c.ip_address_number), C.uint16_t(ip_endpoint.Port))),
	}
}

func (ip_endpoint *IPEndPoint) UDPAddr() *net.UDPAddr {
	ip_buf := make([]byte, 16)
	ip_sz := C.ip_endpoint_ip_address(ip_endpoint.ip_end_point, unsafe.Pointer(&ip_buf[0]))
	port := int(C.ip_endpoint_port(ip_endpoint.ip_end_point))
	return &net.UDPAddr{
		IP:   net.IP(ip_buf[:int(ip_sz)]),
		Port: port,
	}
}

func DeleteIPEndPoint(ip_endpoint IPEndPoint) {
	C.delete_ip_end_point(ip_endpoint.ip_end_point)
}

func CreateQuicDispatcher(conn *net.UDPConn) QuicDispatcher {
	return QuicDispatcher{
		quic_dispatcher: C.create_quic_dispatcher(unsafe.Pointer(conn)),
	}
}

func (d *QuicDispatcher) ProcessPacket(self_address *net.UDPAddr, peer_address *net.UDPAddr, buffer []byte) {
	packet := CreateQuicEncryptedPacket(buffer)
	defer DeleteQuicEncryptedPacket(packet)
	self_address_c := CreateIPEndPoint(self_address)
	defer DeleteIPEndPoint(self_address_c)
	peer_address_c := CreateIPEndPoint(peer_address)
	defer DeleteIPEndPoint(peer_address_c)
	C.quic_dispatcher_process_packet(d.quic_dispatcher, self_address_c.ip_end_point, peer_address_c.ip_end_point, packet.encrypted_packet)
}

//export WriteToUDP
func WriteToUDP(conn_c unsafe.Pointer, ip_endpoint_c unsafe.Pointer, buffer_c unsafe.Pointer, length_c C.size_t) {
	conn := (*net.UDPConn)(conn_c)
	ip_endpoint := IPEndPoint{
		ip_end_point: ip_endpoint_c,
	}
	peer_addr := ip_endpoint.UDPAddr()
	buf := C.GoBytes(buffer_c, C.int(length_c))
	conn.WriteToUDP(buf, peer_addr)
	fmt.Println("******************************************************************")
	fmt.Println(int(length_c), conn, ip_endpoint, peer_addr)
}

func main() {
	fmt.Printf("hello, world\n")
	C.initialize()
	C.set_log_level(-1)
	//C.test_quic()

	buf := make([]byte, 65535)
	listen_addr := net.UDPAddr{
		Port: 8080,
		IP:   net.ParseIP("0.0.0.0"),
	}
	conn, err := net.ListenUDP("udp4", &listen_addr)
	if err != nil {
		panic(err)
	}
	dispatcher := CreateQuicDispatcher(conn)
	for {
		n, peer_addr, err := conn.ReadFromUDP(buf)

		if err != nil {
			panic(err)
		}
		dispatcher.ProcessPacket(&listen_addr, peer_addr, buf[:n])
	}
}
