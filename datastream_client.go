package goquic

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/oleiade/lane"
)

// implement OutgoingDataStreamCreator for Client
type SpdyClientSession struct {
	conn *Conn
}

func (c *SpdyClientSession) CreateOutgoingDynamicStream() DataStreamProcessor {
	return &SpdyClientStream{
		conn: c.conn,
	}
}

// implement DataStreamProcessor for Client
type SpdyClientStream struct {
	// not goroutine-safe
	conn             *Conn
	quicClientStream *QuicClientStream
	pendingReads     *lane.Deque
	header           http.Header
	headerParsed     bool
	trailer          http.Header
	trailerParsed    bool
	// True readFinished means that this stream is half-closed on read-side
	readFinished bool
	// True writeFinished means that this stream is half-closed on write-side
	writeFinished bool
	// True when stream is closed fully
	closed bool
}

func (stream *SpdyClientStream) OnInitialHeadersComplete(header http.Header, peerAddress string) {
	stream.header = header
	stream.headerParsed = true
}

func (stream *SpdyClientStream) OnTrailingHeadersComplete(header http.Header) {
	stream.trailer = header
	stream.trailerParsed = true
}

func (stream *SpdyClientStream) OnDataAvailable(data []byte, isClosed bool) {
	stream.pendingReads.Append(data)
	if isClosed {
		stream.readFinished = true
	}
}

// called on Stream closing. This may be called when both read/write side is closed or there is some error so that stream is force closed (in libquic side).
func (stream *SpdyClientStream) OnClose() {
	stream.closed = true
}

func (stream *SpdyClientStream) Header() (http.Header, error) {
	for stream.pendingReads.Empty() {
		stream.conn.waitForEvents()
	}

	if stream.headerParsed {
		return stream.header, nil
	} else {
		return http.Header{}, errors.New("Cannot read header")
	}
}

func (stream *SpdyClientStream) Trailer() http.Header {
	if !stream.closed {
		for stream.pendingReads.Empty() {
			stream.conn.waitForEvents()
		}
	}

	if stream.trailerParsed {
		return stream.trailer
	} else {
		return http.Header{}
	}
}

func (stream *SpdyClientStream) Read(p []byte) (int, error) {
	stream.conn.processEventsWithDeadline(time.Now()) // Process any pending events

	// We made sure we've processed all events. So pendingReads.Empty() means that it is really empty
	if stream.closed && stream.pendingReads.Empty() {
		return 0, io.EOF
	}

	// Wait for body
	for stream.pendingReads.Empty() {
		stream.conn.waitForEvents()
		if stream.closed && stream.pendingReads.Empty() {
			return 0, io.EOF
		}
	}

	buffer := stream.pendingReads.Shift().([]byte)
	if len(p) < len(buffer) {
		stream.pendingReads.Prepend(buffer[len(p):])
		return copy(p, buffer[:len(p)]), nil
	} else {
		return copy(p, buffer), nil
	}
}

func (stream *SpdyClientStream) WriteHeader(header http.Header, isBodyEmpty bool) {
	stream.quicClientStream.WriteHeader(header, isBodyEmpty)
	if isBodyEmpty {
		stream.writeFinished = true
	}
}

func (stream *SpdyClientStream) Write(buf []byte) (int, error) {
	if stream.writeFinished {
		return 0, errors.New("Write already finished")
	}
	stream.quicClientStream.WriteOrBufferData(buf, false)
	return len(buf), nil
}

func (stream *SpdyClientStream) FinWrite() error {
	if stream.writeFinished {
		return errors.New("Write already finished")
	}
	stream.quicClientStream.WriteOrBufferData(nil, true)
	stream.writeFinished = true
	return nil
}
