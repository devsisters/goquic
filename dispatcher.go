package goquic

// #include <stddef.h>
// #include "adaptor.h"
import "C"
import (
	"net"
	"unsafe"
)

type QuicDispatcher struct {
	quicDispatcher          unsafe.Pointer
	quicServerSessions      []*QuicServerSession
	taskRunner              *TaskRunner
	createQuicServerSession func() DataStreamCreator
}

type QuicServerSession struct {
	quicServerSession unsafe.Pointer
	quicServerStreams []*QuicSpdyServerStream
	streamCreator     DataStreamCreator
	remoteAddr        *net.UDPAddr
}

type QuicEncryptedPacket struct {
	encryptedPacket unsafe.Pointer
}

func CreateQuicDispatcher(conn *net.UDPConn, createQuicServerSession func() DataStreamCreator, taskRunner *TaskRunner) *QuicDispatcher {
	dispatcher := &QuicDispatcher{
		createQuicServerSession: createQuicServerSession,
		taskRunner:              taskRunner,
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
		streamCreator:     userSession,
		// TODO(serialx): Set remoteAddr here
	}
	dispatcher.quicServerSessions = append(dispatcher.quicServerSessions, session) // TODO(hodduc): cleanup

	return unsafe.Pointer(session)
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
