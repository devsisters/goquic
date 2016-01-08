package goquic

import (
	"bytes"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/oleiade/lane"
)

type Conn struct {
	sync.Mutex
	addr        *net.UDPAddr
	sock        *net.UDPConn
	quicClient  *QuicClient
	readChan    chan UdpData
	writer      *ClientWriter
	buffer      bytes.Buffer
	header      http.Header
	readQuitCh  chan bool
	writeQuitCh chan bool
	closed      bool
}

type errorString struct {
	s string
}

func (e *errorString) Error() string {
	return e.s
}

func (c *Conn) Close() (err error) {
	if !c.closed {
		c.quicClient.SendConnectionClosePacket()
		c.readQuitCh <- true
		c.closed = true
		<-c.writeQuitCh // Wait until all writing (incluing QUIC_PEER_GOING_AWAY) has done
	}
	return c.quicClient.Close()
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

func (c *Conn) processEvents() {
	c.processEventsWithDeadline(time.Time{})
}

func (c *Conn) processEventsWithDeadline(deadline time.Time) {
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
		if len(result.Buf) == 0 {
			break
		}
		if !ok || c.closed {
			break
		}
		c.quicClient.ProcessPacket(localAddr, result.Addr, result.Buf)
	case <-c.quicClient.taskRunner.WaitTimer():
		if c.closed {
			panic("debug")
			break
		}
		c.quicClient.taskRunner.DoTasks()
	case <-timeoutCh:
		// Break when past deadline
	}
	c.quicClient.taskRunner.DoTasks()
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
	return qc.IsConnected()
}

func (c *Conn) CreateStream() *SpdyClientStream {
	quicClientStream := c.quicClient.CreateReliableQuicStream()
	stream := &SpdyClientStream{
		conn:             c,
		quicClientStream: quicClientStream,
		pendingReads:     lane.NewDeque(),
	}
	quicClientStream.userStream = stream
	return stream
}

func (c *Conn) Writer() *ClientWriter {
	return c.writer
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
		addr:        addr,
		sock:        conn_udp,
		readQuitCh:  make(chan bool, 1),
		writeQuitCh: make(chan bool, 1),
	}

	createSpdyClientSession := func() OutgoingDataStreamCreator {
		return &SpdyClientSession{conn: quic_conn}
	}

	taskRunner := CreateTaskRunner()
	proofVerifier := CreateProofVerifier()
	quicClient, err := CreateQuicClient(addr, quic_conn, createSpdyClientSession, taskRunner, proofVerifier)
	if err != nil {
		return nil, err
	}
	quic_conn.quicClient = quicClient

	quic_conn.readChan = make(chan UdpData)
	quic_conn.writer = NewClientWriter(make(chan UdpData, 1000)) // TODO(serialx, hodduc): Optimize buffer size

	go func() {
		for dat := range quic_conn.writer.Ch {
			quic_conn.sock.Write(dat.Buf)
		}
		quic_conn.sock.Close()
		quic_conn.writeQuitCh <- true
	}()

	go func() {
		buf := make([]byte, 65535)

	Loop:
		for {
			quic_conn.sock.SetReadDeadline(time.Now().Add(time.Second / 2)) // TIMEOUT = 0.5 sec
			n, peer_addr, err := quic_conn.sock.ReadFromUDP(buf)

			if err == nil {
				buf_new := make([]byte, n)
				copy(buf_new, buf) // XXX(hodduc) buffer copy?

				select {
				case <-quic_conn.readQuitCh:
					break Loop
				case quic_conn.readChan <- UdpData{Addr: peer_addr, Buf: buf_new}:
				}
			} else if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				select {
				case <-quic_conn.readQuitCh:
					break Loop
				default:
				}
			} else {
				panic(err)
			}
		}
		close(quic_conn.writer.Ch)
	}()

	if quic_conn.Connect() == false {
		return nil, &errorString{"Cannot connect"}
	}

	return quic_conn, nil
}
