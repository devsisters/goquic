package goquic

// #include <stddef.h>
// #include "src/adaptor.h"
import "C"
import (
	"net/http"
	"unsafe"
)

//   (~= QuicSpdy(Server|Client)Stream)
type DataStreamProcessor interface {
	OnStreamHeadersComplete(data []byte)
	OnDataAvailable(data []byte, isClosed bool)
	OnClose()
}

//   (~= QuicServerSession)
type IncomingDataStreamCreator interface {
	CreateIncomingDynamicStream(quicServerStream *QuicServerStream, streamId uint32) DataStreamProcessor
}

//   (~= QuicClientSession)
type OutgoingDataStreamCreator interface {
	CreateOutgoingDynamicStream() DataStreamProcessor
}

type QuicStream interface {
	UserStream() DataStreamProcessor
	WriteHeader(header http.Header, is_body_empty bool)
	WriteOrBufferData(body []byte, fin bool)
}

/*
             (Incoming/Outgoing)DataStreamCreator (a.k.a Session)
                                  |
                                  |   creates domain-specific stream (i.e. spdy, ...)
                                  v
   QuicStream -- owns -->  DataStreamProcessor

*/

//export CreateIncomingDynamicStream
func CreateIncomingDynamicStream(session_c unsafe.Pointer, stream_id uint32, wrapper_c unsafe.Pointer) unsafe.Pointer {
	session := (*QuicServerSession)(session_c)
	stream := &QuicServerStream{
		session: session,
		wrapper: wrapper_c,
	}
	userStream := session.streamCreator.CreateIncomingDynamicStream(stream, stream_id)
	stream.userStream = userStream

	// This is to prevent garbage collection. This is cleaned up on QuicServerStream.OnClose()
	session.quicServerStreams[stream] = true

	return unsafe.Pointer(stream)
}

//export GoQuicSpdyServerStreamOnStreamHeadersComplete
func GoQuicSpdyServerStreamOnStreamHeadersComplete(go_quic_spdy_server_stream unsafe.Pointer, data unsafe.Pointer, data_len uint32) {
	stream := (*QuicServerStream)(go_quic_spdy_server_stream)
	buf := C.GoBytes(data, C.int(data_len))
	stream.UserStream().OnStreamHeadersComplete(buf)
}

//export GoQuicSpdyServerStreamOnDataAvailable
func GoQuicSpdyServerStreamOnDataAvailable(go_quic_spdy_server_stream unsafe.Pointer, data unsafe.Pointer, data_len uint32, is_closed C.int) {
	stream := (*QuicServerStream)(go_quic_spdy_server_stream)
	buf := C.GoBytes(data, C.int(data_len))
	stream.UserStream().OnDataAvailable(buf, (is_closed > 0))
}

//export GoQuicSpdyServerStreamOnClose
func GoQuicSpdyServerStreamOnClose(go_quic_spdy_server_stream unsafe.Pointer) {
	stream := (*QuicServerStream)(go_quic_spdy_server_stream)
	stream.UserStream().OnClose()
}

//export GoQuicSpdyClientStreamOnStreamHeadersComplete
func GoQuicSpdyClientStreamOnStreamHeadersComplete(go_quic_spdy_client_stream unsafe.Pointer, data unsafe.Pointer, data_len uint32) {
	stream := (*QuicClientStream)(go_quic_spdy_client_stream)
	buf := C.GoBytes(data, C.int(data_len))
	stream.UserStream().OnStreamHeadersComplete(buf)
}

//export GoQuicSpdyClientStreamOnDataAvailable
func GoQuicSpdyClientStreamOnDataAvailable(go_quic_spdy_client_stream unsafe.Pointer, data unsafe.Pointer, data_len uint32, is_closed C.int) {
	stream := (*QuicClientStream)(go_quic_spdy_client_stream)
	buf := C.GoBytes(data, C.int(data_len))
	stream.UserStream().OnDataAvailable(buf, (is_closed > 0))
}

//export GoQuicSpdyClientStreamOnClose
func GoQuicSpdyClientStreamOnClose(go_quic_spdy_client_stream unsafe.Pointer) {
	stream := (*QuicClientStream)(go_quic_spdy_client_stream)
	stream.UserStream().OnClose()
}

//export UnregisterQuicServerStreamFromSession
func UnregisterQuicServerStreamFromSession(go_stream_c unsafe.Pointer) {
	stream := (*QuicServerStream)(go_stream_c)
	delete(stream.session.quicServerStreams, stream)
}

//export UnregisterQuicClientStreamFromSession
func UnregisterQuicClientStreamFromSession(go_stream_c unsafe.Pointer) {
	stream := (*QuicClientStream)(go_stream_c)
	delete(stream.session.quicClientStreams, stream)
}
