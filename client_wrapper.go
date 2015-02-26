package goquic

// #cgo CXXFLAGS: -DUSE_OPENSSL=1 -std=gnu++11
// #cgo LDFLAGS: -pthread -lgoquic -lquic -lssl -lcrypto -lstdc++ -lm
// #cgo darwin LDFLAGS: -framework CoreFoundation -framework Cocoa
// #include <stddef.h>
// #include "adaptor.h"
// #include "adaptor_client.h"
import "C"
import (
	"net"
	"net/http"
	"strings"
	"time"
	"unsafe"
)

type QuicConn interface { // implements net.Conn
	Close() error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	Socket() *net.UDPConn
}

// TODO(hodduc) multi-stream support ?
type QuicClient struct {
	addr                    *net.UDPAddr
	conn                    QuicConn
	session                 *QuicClientSession
	createQuicClientSession func() DataStreamCreator
	taskRunner              *TaskRunner
}

type QuicClientSession struct {
	quicClientSession unsafe.Pointer
	quicClientStreams []*QuicClientStream
	streamCreator     DataStreamCreator
}

func (s *QuicClientSession) NumActiveRequests() int {
	return int(C.quic_client_session_num_active_requests(s.quicClientSession))
}

type QuicClientStream struct {
	UserStream DataStreamProcessor
	wrapper    unsafe.Pointer
	session    *QuicClientSession
}

func CreateQuicClient(addr *net.UDPAddr, conn QuicConn, createQuicClientSession func() DataStreamCreator, taskRunner *TaskRunner) (qc *QuicClient, err error) {
	return &QuicClient{
		addr:                    addr,
		conn:                    conn,
		taskRunner:              taskRunner,
		createQuicClientSession: createQuicClientSession,
	}, nil
}

func (qc *QuicClient) StartConnect() {
	addr_c := CreateIPEndPoint(qc.addr)
	qc.session = &QuicClientSession{
		quicClientSession: C.create_go_quic_client_session_and_initialize(unsafe.Pointer(qc.conn.Socket()), unsafe.Pointer(qc.taskRunner), addr_c.ipEndPoint), // Deleted on QuicClient.Close()
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
		UserStream: qc.session.streamCreator.CreateOutgoingDataStream(), // Deleted on qc.Close()
		session:    qc.session,
	}
	stream.wrapper = C.quic_client_session_create_reliable_quic_stream(qc.session.quicClientSession, unsafe.Pointer(stream))

	qc.session.quicClientStreams = append(qc.session.quicClientStreams, stream)
	return stream
}

func (qc *QuicClient) ProcessPacket(self_address *net.UDPAddr, peer_address *net.UDPAddr, buffer []byte) {
	packet := CreateQuicEncryptedPacket(buffer)
	defer DeleteQuicEncryptedPacket(packet)
	self_address_c := CreateIPEndPoint(self_address)
	defer DeleteIPEndPoint(self_address_c)
	peer_address_c := CreateIPEndPoint(peer_address)
	defer DeleteIPEndPoint(peer_address_c)

	C.go_quic_client_session_process_packet(qc.session.quicClientSession, self_address_c.ipEndPoint, peer_address_c.ipEndPoint, packet.encryptedPacket)
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

func (stream *QuicClientStream) WriteHeader(header http.Header, is_body_empty bool) {
	header_c := C.initialize_map()
	for key, values := range header {
		value := strings.Join(values, ", ")
		C.insert_map(header_c, C.CString(key), C.CString(value))
	}

	if is_body_empty {
		C.quic_reliable_client_stream_write_headers(stream.wrapper, header_c, 1)
	} else {
		C.quic_reliable_client_stream_write_headers(stream.wrapper, header_c, 0)
	}
}

func (stream *QuicClientStream) WriteOrBufferData(body []byte, fin bool) {
	fin_int := C.int(0)
	if fin {
		fin_int = C.int(1)
	}

	if len(body) == 0 {
		C.quic_reliable_client_stream_write_or_buffer_data(stream.wrapper, (*C.char)(unsafe.Pointer(nil)), C.size_t(0), fin_int)
	} else {
		C.quic_reliable_client_stream_write_or_buffer_data(stream.wrapper, (*C.char)(unsafe.Pointer(&body[0])), C.size_t(len(body)), fin_int)
	}
}

func (writer *QuicClientStream) ProcessData(buf []byte) uint32 {
	return uint32(writer.UserStream.ProcessData(writer, buf))
}

func (writer *QuicClientStream) OnFinRead() {
	writer.UserStream.OnFinRead(writer)
}

func (writer *QuicClientStream) OnClose() {
	writer.UserStream.OnClose(writer)
}
