package goquic

import (
	"bytes"
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

func (s *SpdyServerSession) CreateIncomingDynamicStream(stream_id uint32) DataStreamProcessor {
	stream := &SpdyServerStream{
		stream_id:     stream_id,
		header_parsed: false,
		server:        s.server,
		buffer:        new(bytes.Buffer),
		sessionFnChan: s.sessionFnChan,
	}
	return stream
}

// implement DataStreamProcessor for Server
type SpdyServerStream struct {
	closed          bool
	stream_id       uint32
	header          http.Header
	header_parsed   bool
	buffer          *bytes.Buffer
	server          *QuicSpdyServer
	sessionFnChan   chan func()
	closeNotifyChan chan bool
}

func (stream *SpdyServerStream) ProcessData(serverStream QuicStream, newBytes []byte) int {
	stream.buffer.Write(newBytes)

	if !stream.header_parsed {
		// We don't want to consume the buffer *yet*, so create a new reader
		reader := bytes.NewReader(stream.buffer.Bytes())
		header, err := spdy.ParseHeaders(reader)
		if err != nil {
			// Header parsing unsuccessful, maybe header is not yet completely received
			// Append it to the buffer for parsing later
			return int(len(newBytes))
		}

		// Header parsing successful
		n, _ := reader.Seek(0, 1)
		// Consume the buffer, the rest of the buffer is the body
		stream.buffer.Next(int(n))

		stream.header_parsed = true
		stream.header = header

		// TODO(serialx): Parsing header should also exist on OnFinRead
	}
	// Process body
	return len(newBytes)
}

func (stream *SpdyServerStream) OnFinRead(quicStream QuicStream) {
	if !stream.header_parsed {
		// TODO(serialx): Send error message
	}
	quicStream.CloseReadSide()

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
		return
		// TODO(serialx): Send error message
	}

	url.Scheme = header.Get(":scheme")
	url.Host = header.Get(":host")
	req.URL = url
	// TODO(serialx): To buffered async read
	req.Body = ioutil.NopCloser(stream.buffer)

	go func() {
		w := &spdyResponseWriter{
			serverStream:  quicStream,
			spdyStream:    stream,
			header:        make(http.Header),
			sessionFnChan: stream.sessionFnChan,
		}
		if stream.server.Handler != nil {
			stream.server.Handler.ServeHTTP(w, req)
		} else {
			http.DefaultServeMux.ServeHTTP(w, req)
		}

		stream.sessionFnChan <- func() {
			if stream.closed {
				return
			}
			quicStream.WriteOrBufferData(make([]byte, 0), true)
		}
	}()
}

func (stream *SpdyServerStream) OnClose(quicStream QuicStream) {
	if stream.closeNotifyChan != nil && !stream.closed {
		stream.closeNotifyChan <- true
	}
	stream.closed = true
}

func (stream *SpdyServerStream) closeNotify() <-chan bool {
	if stream.closeNotifyChan == nil {
		stream.closeNotifyChan = make(chan bool, 1)
	}
	return stream.closeNotifyChan
}

type spdyResponseWriter struct {
	serverStream  QuicStream
	spdyStream    *SpdyServerStream
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
