package goquic

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/oleiade/lane"
)

type Conn struct {
	addr       *net.UDPAddr
	sock       *net.UDPConn
	quicClient *QuicClient
	readChan   chan udpData
	buffer     bytes.Buffer
	header     http.Header
}

type Stream struct {
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

type errorString struct {
	s string
}

type udpData struct {
	n    int
	addr *net.UDPAddr
	buf  []byte
}

func (e *errorString) Error() string {
	return e.s
}

func (c *Conn) Close() (err error) {
	return c.sock.Close()
}

func (c *Conn) SetDeadline(t time.Time) (err error) {
	// TODO(hodduc) not supported yet
	return &errorString{"Not Supported"}
}

func (c *Conn) SetReadDeadline(t time.Time) (err error) {
	// TODO(hodduc) not supported yet
	return &errorString{"Not Supported"}
}

func (c *Conn) SetWriteDeadline(t time.Time) (err error) {
	// TODO(hodduc) not supported yet
	return &errorString{"Not Supported"}
}

func (c *Conn) Socket() *net.UDPConn {
	return c.sock
}

func (c *Conn) processEvents() {
	c.processEventsWithDeadline(time.Time{})
}

func (c *Conn) processEventsWithDeadline(deadline time.Time) {
	//c.sock.SetDeadline(time.Now().Add(60 * time.Second)) // TIMEOUT = 60 sec

	localAddr, ok := c.sock.LocalAddr().(*net.UDPAddr)
	if !ok {
		panic("Cannot convert localAddr")
	}

	var timeoutCh <-chan time.Time
	if !deadline.IsZero() {
		timeoutCh = time.After(-time.Since(deadline))
	} else {
		timeoutCh = make(chan time.Time, 1)
	}

	select {
	case result, ok := <-c.readChan:
		if result.n == 0 {
			break
		}
		if !ok {
			break
		}
		c.quicClient.ProcessPacket(localAddr, result.addr, result.buf[:result.n])
	case alarm, ok := <-c.quicClient.taskRunner.AlarmChan:
		if !ok {
			break
		}
		alarm.OnAlarm()
	case <-timeoutCh:
		// Break when past deadline
	}
}

func (c *Conn) waitForEvents() bool {
	c.processEvents()
	return c.quicClient.session.NumActiveRequests() != 0
}

func (c *Conn) Connect() bool {
	qc := c.quicClient
	qc.StartConnect()
	for qc.EncryptionBeingEstablished() {
		// Busy loop waiting for connection to be established
		// TODO(serialx): Maybe we can add some tiny deadlines instead of time.Now to decrease busy waiting?
		c.waitForEvents()
	}
	// TODO(hodduc) when to return false? does waitForEvents fails?
	// TODO(serialx): Ask hodduc what the comment above means
	return true
}

func (c *Conn) CreateStream() *Stream {
	quicClientStream := c.quicClient.CreateReliableQuicStream()
	stream := &Stream{
		conn:             c,
		quicClientStream: quicClientStream,
		pendingReads:     lane.NewQueue(),
	}
	quicClientStream.UserStream.(*ClientStreamImpl).stream = stream
	return stream
}

func (s *Stream) WriteHeader(header http.Header, isBodyEmpty bool) {
	s.quicClientStream.WriteHeader(header, isBodyEmpty)
	if isBodyEmpty {
		s.writeFinished = true
	}
}

func (s *Stream) Write(buf []byte) (int, error) {
	if s.writeFinished {
		return 0, errors.New("Write already finished")
	}
	s.quicClientStream.WriteOrBufferData(buf, false)
	return len(buf), nil
}

func (s *Stream) FinWrite() error {
	if s.writeFinished {
		return errors.New("Write already finished")
	}
	s.quicClientStream.WriteOrBufferData(nil, true)
	s.writeFinished = true
	return nil
}

func (s *Stream) onFinRead() {
	// XXX(serialx): This does not seem to be called at all?
}

func (s *Stream) onClose() {
	s.closed = true
}

func min(a, b int) int {
	if a > b {
		return b
	}
	return a
}

func (s *Stream) ReadHeader() (http.Header, error) {
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
			header, err := ParseHeaders(headerBuf)
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

func (s *Stream) Read(buf []byte) (int, error) {
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
	}

	buffer := s.pendingReads.Dequeue().([]byte)
	return copy(buf, buffer), nil // XXX(serialx): Must do buffering to respect io.Reader specs
}

func Dial(network, address string) (c *Conn, err error) {
	i := strings.LastIndex(network, ":")
	if i > 0 { // has colon
		return nil, &errorString{"Not supported yet"} // TODO
	}

	ra, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}

	return dialQuic(network, net.Addr(ra).(*net.UDPAddr))
}

type ClientSessionImpl struct {
	conn *Conn
}

type ClientStreamImpl struct {
	conn   *Conn
	stream *Stream
}

func (c *ClientSessionImpl) CreateIncomingDataStream(stream_id uint32) DataStreamProcessor {
	// NOT SUPPORTED
	return nil
}

func (c *ClientSessionImpl) CreateOutgoingDataStream() DataStreamProcessor {
	return &ClientStreamImpl{
		conn: c.conn,
	}
}

func (cs *ClientStreamImpl) ProcessData(writer QuicStream, buffer []byte) int {
	//cs.conn.buffer.Write(buffer)
	cs.stream.pendingReads.Enqueue(buffer)
	return len(buffer)
}

func (cs *ClientStreamImpl) OnFinRead(writer QuicStream) {
	cs.stream.onFinRead()
}

func (cs *ClientStreamImpl) OnClose(writer QuicStream) {
	cs.stream.onClose()
}

func dialQuic(network string, addr *net.UDPAddr) (*Conn, error) {
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, &errorString{"Unknown network"}
	}
	if addr == nil {
		return nil, &errorString{"Missing address"}
	}

	conn_udp, err := net.DialUDP(network, nil, addr)
	if err != nil {
		return nil, err
	}

	quic_conn := &Conn{
		addr: addr,
		sock: conn_udp,
	}

	createQuicClientSessionImpl := func() DataStreamCreator {
		return &ClientSessionImpl{conn: quic_conn}
	}

	taskRunner := &TaskRunner{AlarmChan: make(chan *GoQuicAlarm)}
	quicClient, err := CreateQuicClient(addr, quic_conn, createQuicClientSessionImpl, taskRunner)
	if err != nil {
		return nil, err
	}
	quic_conn.quicClient = quicClient

	quic_conn.readChan = make(chan udpData)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, peer_addr, err := quic_conn.sock.ReadFromUDP(buf)
			if err == nil {
				buf_new := make([]byte, n)
				copy(buf_new, buf) // XXX(hodduc) buffer copy?
				quic_conn.readChan <- udpData{n: n, addr: peer_addr, buf: buf_new}
				//			} else if err.(net.Error).Timeout() {
				//				continue
			} else {
				panic(err)
			}
		}
	}()

	if quic_conn.Connect() == false {
		return nil, &errorString{"Cannot connect"}
	}

	return quic_conn, nil
}
