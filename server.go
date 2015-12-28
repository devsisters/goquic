package goquic

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/bradfitz/http2"
	"github.com/vanillahsu/go_reuseport"
)

type QuicSpdyServer struct {
	Addr           string
	Handler        http.Handler
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	MaxHeaderBytes int
	numOfServers   int
	Certificate    tls.Certificate
	isSecure       bool
	sessionFnChan  chan func()
	proofSource    *ProofSource // to prevent garbage collecting
}

func (srv *QuicSpdyServer) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":http"
	}

	readChanArray := make([](chan UdpData), srv.numOfServers)
	writerArray := make([](*ServerWriter), srv.numOfServers)
	connArray := make([](*net.UDPConn), srv.numOfServers)
	serverProofSource := &ServerProofSource{server: srv}
	proofSource := NewProofSource(serverProofSource)
	cryptoConfig := InitCryptoConfig(proofSource)
	srv.proofSource = proofSource

	// N consumers
	for i := 0; i < srv.numOfServers; i++ {
		rch := make(chan UdpData, 500)
		wch := make(chan UdpData, 500) // TODO(serialx, hodduc): Optimize buffer size

		conn, err := reuseport.NewReusablePortPacketConn("udp4", addr)
		if err != nil {
			return err
		}
		defer conn.Close()

		udp_conn, ok := conn.(*net.UDPConn)
		if !ok {
			return errors.New("ListenPacket did not return net.UDPConn")
		}
		connArray[i] = udp_conn

		listen_addr, err := net.ResolveUDPAddr("udp", udp_conn.LocalAddr().String())
		if err != nil {
			return err
		}

		readChanArray[i] = rch
		writerArray[i] = NewServerWriter(wch)
		go srv.Serve(listen_addr, writerArray[i], readChanArray[i], cryptoConfig)
	}

	// N producers
	readFunc := func(conn *net.UDPConn) {
		buf := make([]byte, 65535)

		for {
			n, peer_addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				// TODO(serialx): Don't panic and keep calm...
				panic(err)
			}

			var connId uint64

			switch buf[0] & 0xC {
			case 0xC:
				connId = binary.LittleEndian.Uint64(buf[1:9])
			case 0x8:
				connId = uint64(binary.LittleEndian.Uint32(buf[1:5]))
			case 0x4:
				connId = uint64(binary.LittleEndian.Uint16(buf[1:2]))
			default:
				connId = 0
			}

			buf_new := make([]byte, n)
			copy(buf_new, buf[:n])

			readChanArray[connId%uint64(srv.numOfServers)] <- UdpData{Addr: peer_addr, Buf: buf_new}
			// TODO(hodduc): Minimize heap uses of buf. Consider using sync.Pool standard library to implement buffer pool.
		}
	}

	// N consumers
	writeFunc := func(conn *net.UDPConn, writer *ServerWriter) {
		for dat := range writer.Ch {
			conn.WriteToUDP(dat.Buf, dat.Addr)
		}
	}

	for i := 0; i < srv.numOfServers-1; i++ {
		go writeFunc(connArray[i], writerArray[i])
		go readFunc(connArray[i])
	}

	go writeFunc(connArray[srv.numOfServers-1], writerArray[srv.numOfServers-1])
	readFunc(connArray[srv.numOfServers-1])
	return nil
}

func (srv *QuicSpdyServer) Serve(listen_addr *net.UDPAddr, writer *ServerWriter, readChan chan UdpData, cryptoConfig *ServerCryptoConfig) error {
	runtime.LockOSThread()

	sessionFnChan := make(chan func())

	createSpdySession := func() IncomingDataStreamCreator {
		return &SpdyServerSession{server: srv, sessionFnChan: sessionFnChan}
	}

	dispatcher := CreateQuicDispatcher(writer, createSpdySession, CreateTaskRunner(), cryptoConfig)

	for {
		select {
		case result, ok := <-readChan:
			if !ok {
				break
			}
			dispatcher.ProcessPacket(listen_addr, result.Addr, result.Buf)
		case <-dispatcher.TaskRunner.WaitTimer():
			dispatcher.TaskRunner.DoTasks()
		case fn, ok := <-sessionFnChan:
			if !ok {
				break
			}
			fn()
		}
	}
}

// Provide "Alternate-Protocol" header for QUIC
func AltProtoMiddleware(next http.Handler, port int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Alternate-Protocol", fmt.Sprintf("%d:quic", port))
		next.ServeHTTP(w, r)
	})
}

func parsePort(addr string) (port int, err error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	port, err = net.LookupPort("udp", portStr)
	if err != nil {
		return 0, err
	}

	return port, nil
}

func ListenAndServe(addr string, certFile string, keyFile string, numOfServers int, handler http.Handler) error {
	if handler == nil {
		handler = http.DefaultServeMux
	}
	if certFile == "" || keyFile == "" {
		return errors.New("cert / key should be provided")
	}

	if server, err := NewServer(addr, certFile, keyFile, numOfServers, handler, handler); err != nil {
		return err
	} else {
		return server.ListenAndServe()
	}
}

func ListenAndServeQuicSpdyOnly(addr string, certFile string, keyFile string, numOfServers int, handler http.Handler) error {
	if handler == nil {
		handler = http.DefaultServeMux
	}
	if certFile == "" || keyFile == "" {
		return errors.New("cert / key should be provided")
	}

	if server, err := NewServer(addr, certFile, keyFile, numOfServers, handler, nil); err != nil {
		return err
	} else {
		return server.ListenAndServe()
	}
}

func NewServer(addr string, certFile string, keyFile string, numOfServers int, quicHandler http.Handler, nonQuicHandler http.Handler) (*QuicSpdyServer, error) {
	port, err := parsePort(addr)
	if err != nil {
		return nil, err
	}

	if quicHandler == nil {
		return nil, errors.New("quic handler should be provided")
	}

	if nonQuicHandler != nil {
		go func() {
			httpServer := &http.Server{Addr: addr, Handler: AltProtoMiddleware(nonQuicHandler, port)}
			http2.ConfigureServer(httpServer, nil)

			if certFile != "" && keyFile != "" {
				if err := httpServer.ListenAndServeTLS(certFile, keyFile); err != nil {
					panic(err)
				}
			} else {
				if err := httpServer.ListenAndServe(); err != nil {
					panic(err)
				}
			}
		}()
	}

	server := &QuicSpdyServer{Addr: addr, Handler: quicHandler, numOfServers: numOfServers}
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}

		server.isSecure = true
		server.Certificate = cert
	} else {
		server.isSecure = false
	}

	return server, nil
}
