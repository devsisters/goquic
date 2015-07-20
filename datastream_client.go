package goquic

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/devsisters/goquic/spdy"
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
	conn             *Conn
	quicClientStream *QuicClientStream
	pendingReads     *lane.Queue
	buf              bytes.Buffer
	header           http.Header
	headerParsed     bool
	// True writeFinished means that this stream is half-closed on our side
	writeFinished bool
	// True when connection is closed fully
	closed bool
}

func (s *SpdyClientStream) ProcessData(writer QuicStream, buffer []byte) int {
	//cs.conn.buffer.Write(buffer)
	s.pendingReads.Enqueue(buffer)
	return len(buffer)
}

func (s *SpdyClientStream) OnFinRead(writer QuicStream) {
	// XXX(serialx): This does not seem to be called at all?
}

func (s *SpdyClientStream) OnClose(writer QuicStream) {
	s.closed = true
}

func (s *SpdyClientStream) ReadHeader() (http.Header, error) {
	if !s.headerParsed {
		// Read until header parsing is successful
		for {
			for s.pendingReads.Empty() {
				s.conn.waitForEvents()
			}

			_, err := s.buf.Write(s.pendingReads.Dequeue().([]byte))
			if err != nil {
				return nil, err
			}

			headerBuf := bytes.NewBuffer(s.buf.Bytes()) // Create a temporary buf just in case for parsing failure
			header, err := spdy.ParseHeaders(headerBuf)
			if err == nil { // If parsing successful
				// XXX(serialx): Is it correct to assume headers are in proper packet frame boundary?
				//               What if theres some parts of body left in headerBuf?
				s.header = header
				s.headerParsed = true
				break
			}
		}
	}

	return s.header, nil
}

func (s *SpdyClientStream) Read(buf []byte) (int, error) {
	s.conn.processEventsWithDeadline(time.Now()) // Process any pending events

	// We made sure we've processed all events. So pendingReads.Empty() means that it is really empty
	if s.closed && s.pendingReads.Empty() {
		return 0, io.EOF
	}

	if !s.headerParsed {
		s.ReadHeader()
	}

	// Wait for body
	for s.pendingReads.Empty() {
		s.conn.waitForEvents()
		if s.closed && s.pendingReads.Empty() {
			return 0, io.EOF
		}
	}

	buffer := s.pendingReads.Dequeue().([]byte)
	return copy(buf, buffer), nil // XXX(serialx): Must do buffering to respect io.Reader specs
}

func (s *SpdyClientStream) WriteHeader(header http.Header, isBodyEmpty bool) {
	s.quicClientStream.WriteHeader(header, isBodyEmpty)
	if isBodyEmpty {
		s.writeFinished = true
	}
}

func (s *SpdyClientStream) Write(buf []byte) (int, error) {
	if s.writeFinished {
		return 0, errors.New("Write already finished")
	}
	s.quicClientStream.WriteOrBufferData(buf, false)
	return len(buf), nil
}

func (s *SpdyClientStream) FinWrite() error {
	if s.writeFinished {
		return errors.New("Write already finished")
	}
	s.quicClientStream.WriteOrBufferData(nil, true)
	s.writeFinished = true
	return nil
}
