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

// Note that the buffer is NOT copied. So it is the callers responsibility to retain the buffer until it is processed by QuicConnection
func CreateQuicEncryptedPacket(buffer []byte) QuicEncryptedPacket {
	return QuicEncryptedPacket{
		encryptedPacket: C.create_quic_encrypted_packet((*C.char)(unsafe.Pointer(&buffer[0])), C.size_t(len(buffer))),
	}
}

func DeleteQuicEncryptedPacket(packet QuicEncryptedPacket) {
	C.delete_quic_encrypted_packet(packet.encryptedPacket)
}
