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
	proofVerifier           *ProofVerifier
}

type QuicClientSession struct {
	quicClientSession_c unsafe.Pointer
	quicClientStreams   map[*QuicClientStream]bool
	streamCreator       OutgoingDataStreamCreator
}

func (s *QuicClientSession) NumActiveRequests() int {
	return int(C.quic_client_session_num_active_requests(s.quicClientSession_c))
}

func CreateQuicClient(addr *net.UDPAddr, conn QuicConn, createQuicClientSession func() OutgoingDataStreamCreator, taskRunner *TaskRunner, proofVerifier *ProofVerifier) (qc *QuicClient, err error) {
	return &QuicClient{
		addr:                    addr,
		conn:                    conn,
		taskRunner:              taskRunner,
		createQuicClientSession: createQuicClientSession,
		proofVerifier:           proofVerifier,
	}, nil
}

func (qc *QuicClient) StartConnect() {
	addr := CreateIPEndPoint(qc.addr)
	qc.session = &QuicClientSession{
		quicClientSession_c: C.create_go_quic_client_session_and_initialize(
			C.GoPtr(clientWriterPtr.Set(qc.conn.Writer())),
			C.GoPtr(taskRunnerPtr.Set(qc.taskRunner)),
			C.GoPtr(proofVerifierPtr.Set(qc.proofVerifier)),
			(*C.uint8_t)(unsafe.Pointer(&addr.packed[0])),
			C.size_t(len(addr.packed)),
			C.uint16_t(addr.port)), // Deleted on QuicClient.Close(),
		quicClientStreams: make(map[*QuicClientStream]bool),
		streamCreator:     qc.createQuicClientSession(),
	}
}

func (qc *QuicClient) EncryptionBeingEstablished() bool {
	v := C.go_quic_client_encryption_being_established(qc.session.quicClientSession_c)
	return (v != 0)
}

func (qc *QuicClient) IsConnected() bool {
	v := C.go_quic_client_session_is_connected(qc.session.quicClientSession_c)
	return (v != 0)
}

func (qc *QuicClient) CreateReliableQuicStream() *QuicClientStream {
	stream := &QuicClientStream{
		userStream: qc.session.streamCreator.CreateOutgoingDynamicStream(), // Deleted on qc.Close()
		session:    qc.session,
	}
	stream.wrapper = C.quic_client_session_create_reliable_quic_stream(qc.session.quicClientSession_c, C.GoPtr(quicClientStreamPtr.Set(stream)))

	qc.session.quicClientStreams[stream] = true
	return stream
}

func (qc *QuicClient) ProcessPacket(self_address *net.UDPAddr, peer_address *net.UDPAddr, buffer []byte) {
	self_address_p := CreateIPEndPoint(self_address)
	peer_address_p := CreateIPEndPoint(peer_address)
	C.go_quic_client_session_process_packet(
		qc.session.quicClientSession_c,
		(*C.uint8_t)(unsafe.Pointer(&self_address_p.packed[0])),
		C.size_t(len(self_address_p.packed)),
		C.uint16_t(self_address_p.port),
		(*C.uint8_t)(unsafe.Pointer(&peer_address_p.packed[0])),
		C.size_t(len(peer_address_p.packed)),
		C.uint16_t(peer_address_p.port),
		(*C.char)(unsafe.Pointer(&buffer[0])), C.size_t(len(buffer)),
	)
}

func (qc *QuicClient) SendConnectionClosePacket() {
	C.go_quic_client_session_connection_send_connection_close_packet(qc.session.quicClientSession_c)
}

func (qc *QuicClient) Close() (err error) {
	if qc.session != nil {
		C.delete_go_quic_client_session(qc.session.quicClientSession_c)
		qc.session = nil
	}
	return nil
}
