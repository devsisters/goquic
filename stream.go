package goquic

// #include <stddef.h>
// #include "src/adaptor.h"
import "C"
import (
	"net/http"
	"strings"
	"unsafe"
)

//   (For QuicSpdyServerStream)
type DataStreamProcessor interface {
	ProcessData(writer QuicStream, buffer []byte) int
	// Called when there's nothing to read. Called on server XXX(serialx): Not called on client
	OnFinRead(writer QuicStream)
	// Called when the connection is closed. Called on client XXX(serialx): Not called on server
	OnClose(writer QuicStream)
}

//   (For QuicServerSession)
type DataStreamCreator interface {
	CreateIncomingDataStream(streamId uint32) DataStreamProcessor
	CreateOutgoingDataStream() DataStreamProcessor
}

type QuicStream interface {
	UserStream() DataStreamProcessor
	WriteHeader(header http.Header, is_body_empty bool)
	WriteOrBufferData(body []byte, fin bool)
	CloseReadSide()
}

type QuicSpdyServerStream struct {
	userStream DataStreamProcessor
	wrapper    unsafe.Pointer
	session    *QuicServerSession
}

func (writer *QuicSpdyServerStream) UserStream() DataStreamProcessor {
	return writer.userStream
}

func (writer *QuicSpdyServerStream) WriteHeader(header http.Header, is_body_empty bool) {
	header_c := C.initialize_map()
	for key, values := range header {
		value := strings.Join(values, ", ")
		C.insert_map(header_c, (*C.char)(unsafe.Pointer(&[]byte(key)[0])), C.size_t(len(key)),
			(*C.char)(unsafe.Pointer(&[]byte(value)[0])), C.size_t(len(value)))
	}

	if is_body_empty {
		C.quic_spdy_server_stream_write_headers(writer.wrapper, header_c, 1)
	} else {
		C.quic_spdy_server_stream_write_headers(writer.wrapper, header_c, 0)
	}
	C.delete_map(header_c)
}

func (writer *QuicSpdyServerStream) WriteOrBufferData(body []byte, fin bool) {
	fin_int := C.int(0)
	if fin {
		fin_int = C.int(1)
	}

	if len(body) == 0 {
		C.quic_spdy_server_stream_write_or_buffer_data(writer.wrapper, (*C.char)(unsafe.Pointer(nil)), C.size_t(0), fin_int)
	} else {
		C.quic_spdy_server_stream_write_or_buffer_data(writer.wrapper, (*C.char)(unsafe.Pointer(&body[0])), C.size_t(len(body)), fin_int)
	}
}

func (writer *QuicSpdyServerStream) CloseReadSide() {
	C.quic_spdy_server_stream_close_read_side(writer.wrapper)
}

// TODO: delete(writer.session.quicServerStreams, writer)

//export CreateIncomingDataStream
func CreateIncomingDataStream(session_c unsafe.Pointer, stream_id uint32, wrapper_c unsafe.Pointer) unsafe.Pointer {
	session := (*QuicServerSession)(session_c)
	userStream := session.streamCreator.CreateIncomingDataStream(stream_id)

	stream := &QuicSpdyServerStream{
		userStream: userStream,
		session:    session,
		wrapper:    wrapper_c,
	}

	// This is to prevent garbage collection. This is cleaned up on QuicSpdyServerStream.OnClose()
	session.quicServerStreams[stream] = true

	return unsafe.Pointer(stream)
}

//export DataStreamProcessorProcessData
func DataStreamProcessorProcessData(go_data_stream_processor_c unsafe.Pointer, data unsafe.Pointer, data_len uint32, isServer int) uint32 {
	var stream QuicStream
	if isServer > 0 {
		stream = (*QuicSpdyServerStream)(go_data_stream_processor_c)
	} else {
		stream = (*QuicClientStream)(go_data_stream_processor_c)
	}
	buf := C.GoBytes(data, C.int(data_len))
	return uint32(stream.UserStream().ProcessData(stream, buf))
}

//export DataStreamProcessorOnFinRead
func DataStreamProcessorOnFinRead(go_data_stream_processor_c unsafe.Pointer, isServer int) {
	var stream QuicStream
	if isServer > 0 {
		stream = (*QuicSpdyServerStream)(go_data_stream_processor_c)
	} else {
		stream = (*QuicClientStream)(go_data_stream_processor_c)
	}
	stream.UserStream().OnFinRead(stream)
}

//export DataStreamProcessorOnClose
func DataStreamProcessorOnClose(go_data_stream_processor_c unsafe.Pointer, isServer int) {
	var stream QuicStream
	if isServer > 0 {
		stream = (*QuicSpdyServerStream)(go_data_stream_processor_c)
	} else {
		stream = (*QuicClientStream)(go_data_stream_processor_c)
	}
	stream.UserStream().OnClose(stream)
}

//export UnregisterQuicServerStreamFromSession
func UnregisterQuicServerStreamFromSession(go_stream_c unsafe.Pointer) {
	stream := (*QuicSpdyServerStream)(go_stream_c)
	delete(stream.session.quicServerStreams, stream)
}

//export UnregisterQuicClientStreamFromSession
func UnregisterQuicClientStreamFromSession(go_stream_c unsafe.Pointer) {
	stream := (*QuicClientStream)(go_stream_c)
	delete(stream.session.quicClientStreams, stream)
}
