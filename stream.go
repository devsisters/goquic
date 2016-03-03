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
	OnInitialHeadersComplete(data []byte)
	OnTrailingHeadersComplete(data []byte)
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
func CreateIncomingDynamicStream(session_key int64, stream_id uint32, wrapper_c unsafe.Pointer) int64 {
	session := quicServerSessionPtr.Get(session_key)
	stream := &QuicServerStream{
		session: session,
		wrapper: wrapper_c,
	}
	userStream := session.streamCreator.CreateIncomingDynamicStream(stream, stream_id)
	stream.userStream = userStream

	// This is to prevent garbage collection. This is cleaned up on QuicServerStream.OnClose()
	session.quicServerStreams[stream] = true

	return quicServerStreamPtr.Set(stream)
}

//export GoQuicSimpleServerStreamOnInitialHeadersComplete
func GoQuicSimpleServerStreamOnInitialHeadersComplete(quic_server_stream_key int64, data unsafe.Pointer, data_len uint32) {
	stream := quicServerStreamPtr.Get(quic_server_stream_key)
	buf := C.GoBytes(data, C.int(data_len))
	stream.UserStream().OnInitialHeadersComplete(buf)
}

//export GoQuicSimpleServerStreamOnTrailingHeadersComplete
func GoQuicSimpleServerStreamOnTrailingHeadersComplete(quic_server_stream_key int64, data unsafe.Pointer, data_len uint32) {
	stream := quicServerStreamPtr.Get(quic_server_stream_key)
	buf := C.GoBytes(data, C.int(data_len))
	stream.UserStream().OnTrailingHeadersComplete(buf)
}

//export GoQuicSimpleServerStreamOnDataAvailable
func GoQuicSimpleServerStreamOnDataAvailable(quic_server_stream_key int64, data unsafe.Pointer, data_len uint32, is_closed C.int) {
	stream := quicServerStreamPtr.Get(quic_server_stream_key)
	buf := C.GoBytes(data, C.int(data_len))
	stream.UserStream().OnDataAvailable(buf, (is_closed > 0))
}

//export GoQuicSimpleServerStreamOnClose
func GoQuicSimpleServerStreamOnClose(quic_server_stream_key int64) {
	stream := quicServerStreamPtr.Get(quic_server_stream_key)
	stream.UserStream().OnClose()
}

//export GoQuicSpdyClientStreamOnInitialHeadersComplete
func GoQuicSpdyClientStreamOnInitialHeadersComplete(quic_client_stream_key int64, data unsafe.Pointer, data_len uint32) {
	stream := quicClientStreamPtr.Get(quic_client_stream_key)
	buf := C.GoBytes(data, C.int(data_len))
	stream.UserStream().OnInitialHeadersComplete(buf)
}

//export GoQuicSpdyClientStreamOnTrailingHeadersComplete
func GoQuicSpdyClientStreamOnTrailingHeadersComplete(quic_client_stream_key int64, data unsafe.Pointer, data_len uint32) {
	stream := quicClientStreamPtr.Get(quic_client_stream_key)
	buf := C.GoBytes(data, C.int(data_len))
	stream.UserStream().OnTrailingHeadersComplete(buf)
}

//export GoQuicSpdyClientStreamOnDataAvailable
func GoQuicSpdyClientStreamOnDataAvailable(quic_client_stream_key int64, data unsafe.Pointer, data_len uint32, is_closed C.int) {
	stream := quicClientStreamPtr.Get(quic_client_stream_key)
	buf := C.GoBytes(data, C.int(data_len))
	stream.UserStream().OnDataAvailable(buf, (is_closed > 0))
}

//export GoQuicSpdyClientStreamOnClose
func GoQuicSpdyClientStreamOnClose(quic_client_stream_key int64) {
	stream := quicClientStreamPtr.Get(quic_client_stream_key)
	stream.UserStream().OnClose()
}

//export UnregisterQuicServerStreamFromSession
func UnregisterQuicServerStreamFromSession(quic_server_stream_key int64) {
	stream := quicServerStreamPtr.Get(quic_server_stream_key)
	delete(stream.session.quicServerStreams, stream)
	quicServerStreamPtr.Del(quic_server_stream_key)
}

//export UnregisterQuicClientStreamFromSession
func UnregisterQuicClientStreamFromSession(quic_client_stream_key int64) {
	stream := quicClientStreamPtr.Get(quic_client_stream_key)
	delete(stream.session.quicClientStreams, stream)
	quicClientStreamPtr.Del(quic_client_stream_key)
}
