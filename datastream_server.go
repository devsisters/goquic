package goquic

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"

	"github.com/devsisters/goquic/spdy"
)

// implement IncomingDataStreamCreator for Server
type SpdyServerSession struct {
	server        *QuicSpdyServer
	sessionFnChan chan func()
}

func (s *SpdyServerSession) CreateIncomingDynamicStream(quicServerStream *QuicServerStream, streamId uint32) DataStreamProcessor {
	stream := &SimpleServerStream{
		streamId:         streamId,
		server:           s.server,
		buffer:           new(bytes.Buffer),
		sessionFnChan:    s.sessionFnChan,
		quicServerStream: quicServerStream,
	}
	return stream
}

// implement DataStreamProcessor for Server
type SimpleServerStream struct {
	closed           bool
	streamId         uint32 // Just for logging purpose
	header           http.Header
	buffer           *bytes.Buffer
	server           *QuicSpdyServer
	quicServerStream *QuicServerStream
	sessionFnChan    chan func()
	closeNotifyChan  chan bool
}

func (stream *SimpleServerStream) OnInitialHeadersComplete(headerBuf []byte) {
	if header, err := spdy.ParseHeaders(bytes.NewReader(headerBuf)); err != nil {
		// TODO(hodduc) should raise proper error
	} else {
		stream.header = header
	}
}

func (stream *SimpleServerStream) OnTrailingHeadersComplete(headerBuf []byte) {
}

func (stream *SimpleServerStream) OnDataAvailable(data []byte, isClosed bool) {
	stream.buffer.Write(data)
	if isClosed {
		stream.ProcessRequest()
	}
}

func (stream *SimpleServerStream) OnClose() {
	if stream.closeNotifyChan != nil && !stream.closed {
		stream.closeNotifyChan <- true
	}
	stream.closed = true
}

func (stream *SimpleServerStream) ProcessRequest() {
	header := stream.header
	req := new(http.Request)
	req.Method = header.Get(":method")
	req.RequestURI = header.Get(":path")
	req.Proto = header.Get(":version")
	req.Header = header
	req.Host = header.Get(":host")
	// req.RemoteAddr = serverStream. TODO(serialx): Add remote addr
	rawPath := header.Get(":path")

	url, err := url.ParseRequestURI(rawPath)
	if err != nil {
		fmt.Println(" Error! ", err)
		return
		// TODO(serialx): Send error message
	}

	url.Scheme = header.Get(":scheme")
	url.Host = header.Get(":host")
	req.URL = url
	// TODO(serialx): To buffered async read
	req.Body = ioutil.NopCloser(stream.buffer)

	// Remove SPDY headers
	for k, _ := range header {
		if len(k) > 0 && k[0] == ':' {
			header.Del(k)
		}
	}

	go func() {
		w := &spdyResponseWriter{
			serverStream:  stream.quicServerStream,
			spdyStream:    stream,
			header:        make(http.Header),
			sessionFnChan: stream.sessionFnChan,
		}
		if stream.server.Handler != nil {
			stream.server.Handler.ServeHTTP(w, req)
		} else {
			http.DefaultServeMux.ServeHTTP(w, req)
		}
		// TODO:

		stream.sessionFnChan <- func() {
			if stream.closed {
				return
			}
			stream.quicServerStream.WriteOrBufferData(make([]byte, 0), true)
		}
	}()
}

func (stream *SimpleServerStream) closeNotify() <-chan bool {
	if stream.closeNotifyChan == nil {
		stream.closeNotifyChan = make(chan bool, 1)
	}
	return stream.closeNotifyChan
}

// TODO(hodduc): Somehow support trailing headers
type spdyResponseWriter struct {
	serverStream  *QuicServerStream
	spdyStream    *SimpleServerStream
	header        http.Header
	wroteHeader   bool
	sessionFnChan chan func()
}

func (w *spdyResponseWriter) Header() http.Header {
	return w.header
}

func (w *spdyResponseWriter) Write(buffer []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	copiedBuffer := make([]byte, len(buffer))
	copy(copiedBuffer, buffer)
	w.sessionFnChan <- func() {
		if w.spdyStream.closed {
			return
		}
		w.serverStream.WriteOrBufferData(copiedBuffer, false)
	}
	return len(buffer), nil
}

func cloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

func (w *spdyResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	copiedHeader := cloneHeader(w.header)
	w.sessionFnChan <- func() {
		copiedHeader.Set(":status", strconv.Itoa(statusCode))
		copiedHeader.Set(":version", "HTTP/1.1")
		if w.spdyStream.closed {
			return
		}
		w.serverStream.WriteHeader(copiedHeader, false)
	}
	w.wroteHeader = true
}

func (w *spdyResponseWriter) CloseNotify() <-chan bool {
	return w.spdyStream.closeNotify()
}

func (w *spdyResponseWriter) Flush() {
	// TODO(serialx): Support flush
	// Maybe it's not neccessary because QUIC sends packets in a paced interval.
	// I cannot find any flush related functions in current QUIC code,
	// and samples needing Flush seems to work fine.
	// This functionality maybe needed in the future when we plan to buffer user
	// writes in the Go side.
}
