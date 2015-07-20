package goquic

// #include <stddef.h>
// #include "src/adaptor.h"
import "C"
import (
	"net"
	"unsafe"
)

type QuicDispatcher struct {
	quicDispatcher          unsafe.Pointer
	quicServerSessions      map[*QuicServerSession]bool
	TaskRunner              *TaskRunner
	createQuicServerSession func() IncomingDataStreamCreator
}

type QuicServerSession struct {
	quicServerSession unsafe.Pointer
	quicServerStreams map[*QuicServerStream]bool
	streamCreator     IncomingDataStreamCreator // == session
	remoteAddr        *net.UDPAddr
}

type QuicEncryptedPacket struct {
	encryptedPacket unsafe.Pointer
}

func CreateQuicDispatcher(writer *ServerWriter, createQuicServerSession func() IncomingDataStreamCreator, taskRunner *TaskRunner, cryptoConfig *ServerCryptoConfig) *QuicDispatcher {
	dispatcher := &QuicDispatcher{
		quicServerSessions:      make(map[*QuicServerSession]bool),
		TaskRunner:              taskRunner,
		createQuicServerSession: createQuicServerSession,
	}

	dispatcher.quicDispatcher = C.create_quic_dispatcher(unsafe.Pointer(writer), unsafe.Pointer(dispatcher), unsafe.Pointer(taskRunner), cryptoConfig.serverCryptoConfig)
	return dispatcher
}

func (d *QuicDispatcher) ProcessPacket(self_address *net.UDPAddr, peer_address *net.UDPAddr, buffer []byte) {
	C.quic_dispatcher_process_packet(
		d.quicDispatcher,
		CreateIPEndPointPacked(self_address),
		CreateIPEndPointPacked(peer_address),
		(*C.char)(unsafe.Pointer(&buffer[0])), C.size_t(len(buffer)),
	)
}

//export CreateGoSession
func CreateGoSession(dispatcher_c unsafe.Pointer, session_c unsafe.Pointer) unsafe.Pointer {
	dispatcher := (*QuicDispatcher)(dispatcher_c)
	userSession := dispatcher.createQuicServerSession()
	session := &QuicServerSession{
		quicServerSession: session_c,
		quicServerStreams: make(map[*QuicServerStream]bool),
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
func GetProof(proof_source_c unsafe.Pointer, server_ip_c unsafe.Pointer, server_ip_sz C.size_t, hostname_c unsafe.Pointer, hostname_sz_c C.size_t, server_config_c unsafe.Pointer, server_config_sz_c C.size_t, ecdsa_ok_c C.int, out_certs_c ***C.char, out_certs_sz_c *C.int, out_certs_item_sz_c **C.size_t, out_signature_c **C.char, out_signature_sz_c *C.size_t) C.int {
	proofSource := (*ProofSource)(proof_source_c)
	if !proofSource.impl.IsSecure() {
		return C.int(0)
	}

	serverIp := net.IP(C.GoBytes(server_ip_c, C.int(server_ip_sz)))
	hostname := C.GoBytes(hostname_c, C.int(hostname_sz_c))
	serverConfig := C.GoBytes(server_config_c, C.int(server_config_sz_c))
	ecdsaOk := int(ecdsa_ok_c) > 0

	certs, sig := proofSource.impl.GetProof(serverIp, hostname, serverConfig, ecdsaOk)
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
