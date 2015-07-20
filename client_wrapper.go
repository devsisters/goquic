package goquic

// #cgo CXXFLAGS: -DUSE_OPENSSL=1 -std=gnu++11
// #cgo LDFLAGS: -pthread -lgoquic -lquic -lssl -lcrypto -lstdc++ -lm
// #cgo darwin LDFLAGS: -framework CoreFoundation -framework Cocoa
// #include <stddef.h>
// #include "src/adaptor.h"
// #include "src/adaptor_client.h"
import "C"
import (
	"net"
	"time"
	"unsafe"
)

type QuicConn interface { // implements net.Conn
	Close() error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	Writer() *ClientWriter
}

// TODO(hodduc) multi-stream support ?
type QuicClient struct {
	addr                    *net.UDPAddr
	conn                    QuicConn
	session                 *QuicClientSession
	createQuicClientSession func() OutgoingDataStreamCreator
	taskRunner              *TaskRunner
}

type QuicClientSession struct {
	quicClientSession unsafe.Pointer
	quicClientStreams map[*QuicClientStream]bool
	streamCreator     OutgoingDataStreamCreator
}

func (s *QuicClientSession) NumActiveRequests() int {
	return int(C.quic_client_session_num_active_requests(s.quicClientSession))
}

func CreateQuicClient(addr *net.UDPAddr, conn QuicConn, createQuicClientSession func() OutgoingDataStreamCreator, taskRunner *TaskRunner) (qc *QuicClient, err error) {
	return &QuicClient{
		addr:                    addr,
		conn:                    conn,
		taskRunner:              taskRunner,
		createQuicClientSession: createQuicClientSession,
	}, nil
}

func (qc *QuicClient) StartConnect() {
	addr := CreateIPEndPointPacked(qc.addr)
	qc.session = &QuicClientSession{
		quicClientSession: C.create_go_quic_client_session_and_initialize(unsafe.Pointer(qc.conn.Writer()), unsafe.Pointer(qc.taskRunner), addr), // Deleted on QuicClient.Close(),
		quicClientStreams: make(map[*QuicClientStream]bool),
		streamCreator:     qc.createQuicClientSession(),
	}
}

func (qc *QuicClient) EncryptionBeingEstablished() bool {
	v := C.go_quic_client_encryption_being_established(qc.session.quicClientSession)
	return (v != 0)
}

func (qc *QuicClient) IsConnected() bool {
	v := C.go_quic_client_session_is_connected(qc.session.quicClientSession)
	return (v != 0)
}

func (qc *QuicClient) CreateReliableQuicStream() *QuicClientStream {
	stream := &QuicClientStream{
		userStream: qc.session.streamCreator.CreateOutgoingDynamicStream(), // Deleted on qc.Close()
		session:    qc.session,
	}
	stream.wrapper = C.quic_client_session_create_reliable_quic_stream(qc.session.quicClientSession, unsafe.Pointer(stream))

	qc.session.quicClientStreams[stream] = true
	return stream
}

func (qc *QuicClient) ProcessPacket(self_address *net.UDPAddr, peer_address *net.UDPAddr, buffer []byte) {
	C.go_quic_client_session_process_packet(
		qc.session.quicClientSession,
		CreateIPEndPointPacked(self_address),
		CreateIPEndPointPacked(peer_address),
		(*C.char)(unsafe.Pointer(&buffer[0])), C.size_t(len(buffer)),
	)
}

func (qc *QuicClient) SendConnectionClosePacket() {
	C.go_quic_client_session_connection_send_connection_close_packet(qc.session.quicClientSession)
}

func (qc *QuicClient) Close() (err error) {
	if qc.session != nil {
		C.delete_go_quic_client_session(unsafe.Pointer(qc.session.quicClientSession))
		qc.session = nil
	}
	return nil
}
