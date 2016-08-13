package goquic

// #include <stddef.h>
// #include "src/adaptor.h"
import "C"
import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"unsafe"
)

//   (~= QuicSpdy(Server|Client)Stream)
type DataStreamProcessor interface {
	OnInitialHeadersComplete(header http.Header, peerAddress string)
	OnTrailingHeadersComplete(header http.Header)
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
	WriteTrailers(header http.Header)
}

/*
             (Incoming/Outgoing)DataStreamCreator (a.k.a Session)
                                  |
                                  |   creates domain-specific stream (i.e. spdy, ...)
                                  v
   QuicStream -- owns -->  DataStreamProcessor

*/

func createHeader(headers_c *C.struct_GoSpdyHeader) http.Header {
	h := make(http.Header)
	N := int(headers_c.N)

	keysArray := (*[1 << 30](*C.char))(unsafe.Pointer(headers_c.Keys))[:N:N]
	valuesArray := (*[1 << 30](*C.char))(unsafe.Pointer(headers_c.Values))[:N:N]

	keysLen := (*[1 << 30]C.int)(unsafe.Pointer(headers_c.Keys_len))[:N:N]
	valuesLen := (*[1 << 30]C.int)(unsafe.Pointer(headers_c.Values_len))[:N:N]

	for i := 0; i < N; i++ {
		key := C.GoStringN(keysArray[i], keysLen[i])
		value := C.GoStringN(valuesArray[i], valuesLen[i])

		if v, ok := h[key]; !ok {
			h[key] = []string{value}
		} else {
			h[key] = append(v, value)
		}
	}

	return h
}

func digSpdyHeader(header http.Header) ([]byte, []C.int, []byte, []C.int) {
	var keys, values bytes.Buffer
	var keylen, valuelen []C.int

	keylen = make([]C.int, 0, len(header))
	valuelen = make([]C.int, 0, len(header))

	for key, mvalue := range header {
		for index := range mvalue {

			// Due to spdy_utils.cc, all trailer headers key should be lower-case (why?)
			nk, errk := keys.WriteString(strings.ToLower(key))
			nv, errv := values.WriteString(mvalue[index])

			keylen = append(keylen, C.int(nk))
			valuelen = append(valuelen, C.int(nv))

			if errk != nil || errv != nil {
				fmt.Println("buffer write failed", errk, errv)
				break
			}
		}
	}

	return keys.Bytes(), keylen, values.Bytes(), valuelen
}

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
func GoQuicSimpleServerStreamOnInitialHeadersComplete(quic_server_stream_key int64, headers_c *C.struct_GoSpdyHeader, peer_addr unsafe.Pointer, peer_addr_len uint32) {
	stream := quicServerStreamPtr.Get(quic_server_stream_key)
	header := createHeader(headers_c)
	peerAddr := C.GoStringN((*C.char)(peer_addr), (C.int)(peer_addr_len))
	stream.UserStream().OnInitialHeadersComplete(header, peerAddr)
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
func GoQuicSpdyClientStreamOnInitialHeadersComplete(quic_client_stream_key int64, headers_c *C.struct_GoSpdyHeader) {
	stream := quicClientStreamPtr.Get(quic_client_stream_key)
	header := createHeader(headers_c)
	stream.UserStream().OnInitialHeadersComplete(header, "")
}

//export GoQuicSpdyClientStreamOnTrailingHeadersComplete
func GoQuicSpdyClientStreamOnTrailingHeadersComplete(quic_client_stream_key int64, headers_c *C.struct_GoSpdyHeader) {
	stream := quicClientStreamPtr.Get(quic_client_stream_key)
	header := createHeader(headers_c)
	stream.UserStream().OnTrailingHeadersComplete(header)
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
