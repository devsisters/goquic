package goquic

// #include "src/adaptor.h"
import "C"
import (
	"net/http"
	"unsafe"
)

// implement QuicStream
type QuicServerStream struct {
	userStream DataStreamProcessor
	wrapper    unsafe.Pointer
	session    *QuicServerSession
}

func (stream *QuicServerStream) UserStream() DataStreamProcessor {
	return stream.userStream
}

func (stream *QuicServerStream) WriteHeader(header http.Header, is_body_empty bool) {
	keys, keylen, values, valuelen := digSpdyHeader(header)

	if is_body_empty {
		C.quic_simple_server_stream_write_headers(stream.wrapper, C.int(len(keylen)),
			(*C.char)(unsafe.Pointer(&keys[0])), (*C.int)(unsafe.Pointer(&keylen[0])),
			(*C.char)(unsafe.Pointer(&values[0])), (*C.int)(unsafe.Pointer(&valuelen[0])), 1)
	} else {
		C.quic_simple_server_stream_write_headers(stream.wrapper, C.int(len(keylen)),
			(*C.char)(unsafe.Pointer(&keys[0])), (*C.int)(unsafe.Pointer(&keylen[0])),
			(*C.char)(unsafe.Pointer(&values[0])), (*C.int)(unsafe.Pointer(&valuelen[0])), 0)
	}
}

func (stream *QuicServerStream) WriteOrBufferData(body []byte, fin bool) {
	fin_int := C.int(0)
	if fin {
		fin_int = C.int(1)
	}

	if len(body) == 0 {
		C.quic_simple_server_stream_write_or_buffer_data(stream.wrapper, (*C.char)(unsafe.Pointer(nil)), C.size_t(0), fin_int)
	} else {
		C.quic_simple_server_stream_write_or_buffer_data(stream.wrapper, (*C.char)(unsafe.Pointer(&body[0])), C.size_t(len(body)), fin_int)
	}
}

func (stream *QuicServerStream) WriteTrailers(header http.Header) {
	keys, keylen, values, valuelen := digSpdyHeader(header)

	C.quic_simple_server_stream_write_trailers(stream.wrapper, C.int(len(keylen)),
		(*C.char)(unsafe.Pointer(&keys[0])), (*C.int)(unsafe.Pointer(&keylen[0])),
		(*C.char)(unsafe.Pointer(&values[0])), (*C.int)(unsafe.Pointer(&valuelen[0])))
}

// TODO(hodduc): delete(stream.session.quicServerStreams, stream)
