package goquic

// #include <stddef.h>
// #include "src/adaptor.h"
import "C"
import (
	"net/http"
	"unsafe"
)

//   (For Quic(Server|Client)Stream)
type DataStreamProcessor interface {
	ProcessData(writer QuicStream, buffer []byte) int
	// Called when there's nothing to read. Called on server XXX(serialx): Not called on client
	OnFinRead(writer QuicStream)
	// Called when the connection is closed. Called on client XXX(serialx): Not called on server
	OnClose(writer QuicStream)
}

//   (For QuicServerSession)
type IncomingDataStreamCreator interface {
	CreateIncomingDynamicStream(streamId uint32) DataStreamProcessor
}

//   (For QuicClientSession)
type OutgoingDataStreamCreator interface {
	CreateOutgoingDynamicStream() DataStreamProcessor
}

type QuicStream interface {
	UserStream() DataStreamProcessor
	WriteHeader(header http.Header, is_body_empty bool)
	WriteOrBufferData(body []byte, fin bool)
	CloseReadSide()
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
	userStream := session.streamCreator.CreateIncomingDynamicStream(stream_id)

	stream := &QuicServerStream{
		userStream: userStream,
		session:    session,
		wrapper:    wrapper_c,
	}

	// This is to prevent garbage collection. This is cleaned up on QuicServerStream.OnClose()
	session.quicServerStreams[stream] = true

	return unsafe.Pointer(stream)
}

//export DataStreamProcessorProcessData
func DataStreamProcessorProcessData(go_data_stream_processor_c unsafe.Pointer, data unsafe.Pointer, data_len uint32, isServer int) uint32 {
	var stream QuicStream
	if isServer > 0 {
		stream = (*QuicServerStream)(go_data_stream_processor_c)
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
		stream = (*QuicServerStream)(go_data_stream_processor_c)
	} else {
		stream = (*QuicClientStream)(go_data_stream_processor_c)
	}
	stream.UserStream().OnFinRead(stream)
}

//export DataStreamProcessorOnClose
func DataStreamProcessorOnClose(go_data_stream_processor_c unsafe.Pointer, isServer int) {
	var stream QuicStream
	if isServer > 0 {
		stream = (*QuicServerStream)(go_data_stream_processor_c)
	} else {
		stream = (*QuicClientStream)(go_data_stream_processor_c)
	}
	stream.UserStream().OnClose(stream)
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
