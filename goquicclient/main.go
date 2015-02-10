package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/devsisters/goquic"
)

type QuicConnImpl struct {
	addr            *net.UDPAddr
	sock            *net.UDPConn
	quicClient      *goquic.QuicClient
	writeBufferChan chan []byte
	buffer          bytes.Buffer
	header          http.Header
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

func (c *QuicConnImpl) Read(b []byte) (n int, err error) {
	for {
		n, err := c.buffer.Read(b)
		if err == nil {
			return n, err
		}

		c.quicClient.WaitForEvents()
		// TODO(hodduc) more precise error handling
	}
}

func (c *QuicConnImpl) Write(b []byte) (n int, err error) {
	// TODO(hodduc): Minimize heap uses of buf
	buf_new := make([]byte, len(b))
	copy(buf_new, b)

	fmt.Println("Waiting for write .....")

	c.writeBufferChan <- buf_new
	return len(b), nil
}

func (c *QuicConnImpl) Close() (err error) {
	return c.sock.Close()
}

func (c *QuicConnImpl) SetDeadline(t time.Time) (err error) {
	// TODO(hodduc) not supported yet
	return &errorString{"Not Supported"}
}

func (c *QuicConnImpl) SetReadDeadline(t time.Time) (err error) {
	// TODO(hodduc) not supported yet
	return &errorString{"Not Supported"}
}

func (c *QuicConnImpl) SetWriteDeadline(t time.Time) (err error) {
	// TODO(hodduc) not supported yet
	return &errorString{"Not Supported"}
}

func (c *QuicConnImpl) Socket() *net.UDPConn {
	return c.sock
}

func (c *QuicConnImpl) Loop(taskRunner *goquic.TaskRunner) {
	c.sock.SetDeadline(time.Now().Add(60 * time.Second)) // TIMEOUT = 60 sec

	readChan := make(chan udpData)

	go func() {
		buf := make([]byte, 65535)
		for {
			fmt.Println("another reading start ***********************")
			n, peer_addr, err := c.sock.ReadFromUDP(buf)
			fmt.Println("another reading ***********************")
			if err == nil {
				buf_new := make([]byte, n)
				copy(buf_new, buf) // XXX(hodduc) buffer copy?
				readChan <- udpData{n: n, addr: peer_addr, buf: buf_new}
				fmt.Println("********************************************", n)
				//			} else if err.(net.Error).Timeout() {
				//				continue
			} else {
				panic(err)
			}
		}
	}()

	for {
		select {
		case result, ok := <-readChan:
			fmt.Println("Read! ##################################", result.n)
			if result.n == 0 {
				continue
			}
			if !ok {
				break
			}
			localAddr, ok := c.sock.LocalAddr().(*net.UDPAddr)
			if !ok {
				panic("Cannot convert localAddr")
			}
			c.quicClient.ProcessPacket(localAddr, result.addr, result.buf[:result.n])
			fmt.Println("Read Done! ##################################", result.n)
		case alarm, ok := <-taskRunner.AlarmChan:
			fmt.Println("Alarm! ##############################")
			if !ok {
				break
			}
			alarm.OnAlarm()
		case writeBuf, ok := <-c.writeBufferChan:
			fmt.Println("Writebuf! ##############################")
			if !ok {
				break
			}
			stream := c.quicClient.CreateReliableQuicStream()
			stream.WriteHeader(c.header, false)
			stream.WriteOrBufferData(writeBuf, true) // TODO(hodduc): support multi-part upload? (fin = false)
		}
		c.quicClient.Events <- true
	}
}

func Dial(network, address string) (c *QuicConnImpl, err error) {
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

type ClientSession struct {
	conn *QuicConnImpl
}

type ClientStream struct {
	conn *QuicConnImpl
}

func (c *ClientSession) CreateIncomingDataStream(stream_id uint32) goquic.DataStreamProcessor {
	// NOT SUPPORTED
	return nil
}

func (c *ClientSession) CreateOutgoingDataStream() goquic.DataStreamProcessor {
	return &ClientStream{
		conn: c.conn,
	}
}

func (cs *ClientStream) ProcessData(writer goquic.QuicStream, buffer []byte) int {
	cs.conn.buffer.Write(buffer)
	fmt.Println("#########################################################", buffer)
	return len(buffer)
}

func (cs *ClientStream) OnFinRead(writer goquic.QuicStream) {

}

func dialQuic(network string, addr *net.UDPAddr) (*QuicConnImpl, error) {
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, &errorString{"Unknown network"}
	}
	if addr == nil {
		return nil, &errorString{"Missing address"}
	}

	fmt.Println("Connect to ", network, " - ", addr)
	conn_udp, err := net.DialUDP(network, nil, addr)
	if err != nil {
		return nil, err
	}

	quic_conn := &QuicConnImpl{
		addr:            addr,
		sock:            conn_udp,
		writeBufferChan: make(chan []byte),
	}

	createQuicClientSession := func() goquic.DataStreamCreator {
		return &ClientSession{conn: quic_conn}
	}

	taskRunner := &goquic.TaskRunner{AlarmChan: make(chan *goquic.GoQuicAlarm)}
	quicClient, err := goquic.CreateQuicClient(addr, quic_conn, createQuicClientSession, taskRunner)
	if err != nil {
		return nil, err
	}
	quic_conn.quicClient = quicClient

	go quic_conn.Loop(taskRunner)

	if quicClient.Connect() == false {
		return nil, &errorString{"Cannot connect"}
	}

	return quic_conn, nil
}

var host string
var logLevel int

func init() {
	flag.StringVar(&host, "host", "127.0.0.1:8080", "host to connect")
	flag.IntVar(&logLevel, "loglevel", -1, "Log level")
}

func main() {
	goquic.Initialize()
	goquic.SetLogLevel(logLevel)

	conn, err := Dial("udp4", host)
	if err != nil {
		panic(err)
	}

	conn.header = make(http.Header)
	conn.header.Set(":host", "172.24.0.216:8080")
	conn.header.Set(":version", "HTTP/1.0")
	conn.header.Set(":method", "GET")
	conn.header.Set(":path", "/")
	conn.header.Set(":scheme", "http")
	fmt.Fprintf(conn, "GET /") //"GET / HTTP/1.0\r\n\r\n")
	status, err := bufio.NewReader(conn).ReadString('\n')
	fmt.Println(status)
}
