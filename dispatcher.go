package goquic

// #include <stddef.h>
// #include "adaptor.h"
import "C"
import (
	"net"
	"unsafe"
)

type ProofSource interface {
	GetProof(addr *net.UDPAddr, hostname []byte, serverConfig []byte, ecdsaOk bool) (outCerts [][]byte, outSignature []byte)
}

type QuicDispatcher struct {
	quicDispatcher          unsafe.Pointer
	quicServerSessions      map[*QuicServerSession]bool
	taskRunner              *TaskRunner
	createQuicServerSession func() DataStreamCreator
	proofSource             ProofSource
	isSecure                bool
}

type QuicServerSession struct {
	quicServerSession unsafe.Pointer
	quicServerStreams map[*QuicSpdyServerStream]bool
	streamCreator     DataStreamCreator
	remoteAddr        *net.UDPAddr
}

type QuicEncryptedPacket struct {
	encryptedPacket unsafe.Pointer
}

func CreateQuicDispatcher(conn *net.UDPConn, createQuicServerSession func() DataStreamCreator, taskRunner *TaskRunner, proofSource ProofSource, isSecure bool) *QuicDispatcher {
	dispatcher := &QuicDispatcher{
		quicServerSessions:      make(map[*QuicServerSession]bool),
		taskRunner:              taskRunner,
		createQuicServerSession: createQuicServerSession,
		proofSource:             proofSource,
		isSecure:                isSecure,
	}

	dispatcher.quicDispatcher = C.create_quic_dispatcher(unsafe.Pointer(conn), unsafe.Pointer(dispatcher), unsafe.Pointer(taskRunner))
	return dispatcher
}

func (d *QuicDispatcher) ProcessPacket(self_address *net.UDPAddr, peer_address *net.UDPAddr, buffer []byte) {
	packet := CreateQuicEncryptedPacket(buffer)
	defer DeleteQuicEncryptedPacket(packet)
	self_address_c := CreateIPEndPoint(self_address)
	defer DeleteIPEndPoint(self_address_c)
	peer_address_c := CreateIPEndPoint(peer_address)
	defer DeleteIPEndPoint(peer_address_c)
	C.quic_dispatcher_process_packet(d.quicDispatcher, self_address_c.ipEndPoint, peer_address_c.ipEndPoint, packet.encryptedPacket)
}

//export CreateGoSession
func CreateGoSession(dispatcher_c unsafe.Pointer, session_c unsafe.Pointer) unsafe.Pointer {
	dispatcher := (*QuicDispatcher)(dispatcher_c)
	userSession := dispatcher.createQuicServerSession()
	session := &QuicServerSession{
		quicServerSession: session_c,
		quicServerStreams: make(map[*QuicSpdyServerStream]bool),
		streamCreator:     userSession,
		// TODO(serialx): Set remoteAddr here
	}

	// This is to prevent garbage collection. This is cleaned up on DeleteGoSession()
	dispatcher.quicServerSessions[session] = true

	return unsafe.Pointer(session)
}

//export DeleteGoSession
func DeleteGoSession(dispatcher_c unsafe.Pointer, go_session_c unsafe.Pointer) {
	dispatcher := (*QuicDispatcher)(dispatcher_c)
	go_session := (*QuicServerSession)(go_session_c)
	delete(dispatcher.quicServerSessions, go_session)
}

//export GetProof
func GetProof(dispatcher_c unsafe.Pointer, server_ip_c unsafe.Pointer, hostname_c unsafe.Pointer, hostname_sz_c C.size_t, server_config_c unsafe.Pointer, server_config_sz_c C.size_t, ecdsa_ok_c C.int, out_certs_c ***C.char, out_certs_sz_c *C.int, out_certs_item_sz_c **C.size_t, out_signature_c **C.char, out_signature_sz_c *C.size_t) C.int {
	dispatcher := (*QuicDispatcher)(dispatcher_c)

	if !dispatcher.isSecure {
		return C.int(0)
	}

	endpoint := IPEndPoint{
		ipEndPoint: server_ip_c,
	}
	serverIp := endpoint.UDPAddr()
	hostname := C.GoBytes(hostname_c, C.int(hostname_sz_c))
	serverConfig := C.GoBytes(server_config_c, C.int(server_config_sz_c))
	ecdsaOk := int(ecdsa_ok_c) > 0

	certs, sig := dispatcher.proofSource.GetProof(serverIp, hostname, serverConfig, ecdsaOk)
	certsCStrList := make([](*C.char), 0, 10)
	certsCStrSzList := make([](C.size_t), 0, 10)
	for _, outCert := range certs {
		outCert_c := C.CString(string(outCert)) // Must free this C string in C code
		certsCStrList = append(certsCStrList, outCert_c)
		certsCStrSzList = append(certsCStrSzList, C.size_t(len(outCert)))
	}

	*out_certs_c = (**C.char)(unsafe.Pointer(&certsCStrList[0]))
	*out_certs_sz_c = C.int(len(certsCStrList))
	*out_certs_item_sz_c = (*C.size_t)(unsafe.Pointer(&certsCStrSzList[0]))
	*out_signature_c = C.CString(string(sig)) // Must free C string
	*out_signature_sz_c = C.size_t(len(sig))

	return C.int(1)
}

// Note that the buffer is NOT copied. So it is the callers responsibility to retain the buffer until it is processed by QuicConnection
func CreateQuicEncryptedPacket(buffer []byte) QuicEncryptedPacket {
	return QuicEncryptedPacket{
		encryptedPacket: C.create_quic_encrypted_packet((*C.char)(unsafe.Pointer(&buffer[0])), C.size_t(len(buffer))),
	}
}

func DeleteQuicEncryptedPacket(packet QuicEncryptedPacket) {
	C.delete_quic_encrypted_packet(packet.encryptedPacket)
}
