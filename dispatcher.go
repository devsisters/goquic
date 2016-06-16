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
}

type QuicEncryptedPacket struct {
	encryptedPacket unsafe.Pointer
}

func CreateQuicDispatcher(writer *ServerWriter, createQuicServerSession func() IncomingDataStreamCreator, taskRunner *TaskRunner, cryptoConfig *QuicCryptoServerConfig) *QuicDispatcher {
	dispatcher := &QuicDispatcher{
		quicServerSessions:      make(map[*QuicServerSession]bool),
		TaskRunner:              taskRunner,
		createQuicServerSession: createQuicServerSession,
	}

	dispatcher.quicDispatcher = C.create_quic_dispatcher(
		C.GoPtr(serverWriterPtr.Set(writer)), C.GoPtr(quicDispatcherPtr.Set(dispatcher)), C.GoPtr(taskRunnerPtr.Set(taskRunner)), cryptoConfig.cryptoServerConfig)
	return dispatcher
}

func (d *QuicDispatcher) ProcessPacket(self_address *net.UDPAddr, peer_address *net.UDPAddr, buffer []byte) {
	self_address_p := CreateIPEndPoint(self_address)
	peer_address_p := CreateIPEndPoint(peer_address)
	C.quic_dispatcher_process_packet(
		d.quicDispatcher,
		(*C.uint8_t)(unsafe.Pointer(&self_address_p.packed[0])),
		C.size_t(len(self_address_p.packed)),
		C.uint16_t(self_address_p.port),
		(*C.uint8_t)(unsafe.Pointer(&peer_address_p.packed[0])),
		C.size_t(len(peer_address_p.packed)),
		C.uint16_t(peer_address_p.port),
		(*C.char)(unsafe.Pointer(&buffer[0])), C.size_t(len(buffer)),
	)
}

func (d *QuicDispatcher) Statistics() DispatcherStatistics {
	stat := DispatcherStatistics{make([]SessionStatistics, 0)}
	for session, _ := range d.quicServerSessions {
		stat.SessionStatistics = append(stat.SessionStatistics, SessionStatistics{C.quic_server_session_connection_stat(session.quicServerSession)})
	}
	return stat
}

//export CreateGoSession
func CreateGoSession(dispatcher_key int64, session_c unsafe.Pointer) int64 {
	dispatcher := quicDispatcherPtr.Get(dispatcher_key)
	userSession := dispatcher.createQuicServerSession()
	session := &QuicServerSession{
		quicServerSession: session_c,
		quicServerStreams: make(map[*QuicServerStream]bool),
		streamCreator:     userSession,
	}

	// This is to prevent garbage collection. This is cleaned up on DeleteGoSession()
	dispatcher.quicServerSessions[session] = true

	return quicServerSessionPtr.Set(session)
}

//export DeleteGoSession
func DeleteGoSession(dispatcher_key int64, go_session_key int64) {
	dispatcher := quicDispatcherPtr.Get(dispatcher_key)
	go_session := quicServerSessionPtr.Get(go_session_key)
	delete(dispatcher.quicServerSessions, go_session)
	quicServerSessionPtr.Del(go_session_key)
}

//export ReleaseQuicDispatcher
func ReleaseQuicDispatcher(task_runner_key int64) {
	quicDispatcherPtr.Del(task_runner_key)
}

//export ReleaseTaskRunner
func ReleaseTaskRunner(task_runner_key int64) {
	taskRunnerPtr.Del(task_runner_key)
}
