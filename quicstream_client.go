package goquic

// #include "src/adaptor.h"
// #include "src/adaptor_client.h"
import "C"
import (
	"net/http"
	"strings"
	"unsafe"
)

// implement QuicStream
type QuicClientStream struct {
	userStream DataStreamProcessor
	wrapper    unsafe.Pointer
	session    *QuicClientSession
}

func (stream *QuicClientStream) UserStream() DataStreamProcessor {
	return stream.userStream
}

func (stream *QuicClientStream) WriteHeader(header http.Header, is_body_empty bool) {
	header_c := C.initialize_header_block()
	for key, values := range header {
		value := strings.Join(values, ", ")
		C.insert_header_block(header_c, (*C.char)(unsafe.Pointer(&[]byte(key)[0])), C.size_t(len(key)),
			(*C.char)(unsafe.Pointer(&[]byte(value)[0])), C.size_t(len(value)))
	}

	if is_body_empty {
		C.quic_spdy_client_stream_write_headers(stream.wrapper, header_c, 1)
	} else {
		C.quic_spdy_client_stream_write_headers(stream.wrapper, header_c, 0)
	}
	C.delete_header_block(header_c)
}

func (stream *QuicClientStream) WriteOrBufferData(body []byte, fin bool) {
	fin_int := C.int(0)
	if fin {
		fin_int = C.int(1)
	}

	if len(body) == 0 {
		C.quic_spdy_client_stream_write_or_buffer_data(stream.wrapper, (*C.char)(unsafe.Pointer(nil)), C.size_t(0), fin_int)
	} else {
		C.quic_spdy_client_stream_write_or_buffer_data(stream.wrapper, (*C.char)(unsafe.Pointer(&body[0])), C.size_t(len(body)), fin_int)
	}
}
