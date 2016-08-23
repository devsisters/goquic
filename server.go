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

	"github.com/vanillahsu/go_reuseport"
	"golang.org/x/net/http2"
)

type QuicSpdyServer struct {
	Addr           string
	Handler        http.Handler
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	MaxHeaderBytes int
	Certificate    tls.Certificate
	Secret         string
	ServerConfig   *SerializedServerConfig

	numOfServers  int
	isSecure      bool
	statisticsReq [](chan statCallback)
	bufpool       *BytesBufferPool
}

func (srv *QuicSpdyServer) Statistics() (*ServerStatistics, error) {
	if srv.statisticsReq == nil {
		return nil, errors.New("Server not started")
	}

	serverStat := &ServerStatistics{}
	dispatcherStatCh := make(chan DispatcherStatistics)

	go func() {
		for i := 0; i < len(srv.statisticsReq); i++ {
			cb := make(statCallback, 1)
			srv.statisticsReq[i] <- cb         // Send "cb" cannel to dispatcher
			dispatcherStat := <-cb             // Get return value from "cb" channel
			dispatcherStatCh <- dispatcherStat // Send return value to pipeline
		}
		close(dispatcherStatCh)
	}()

	for dispatcherStat := range dispatcherStatCh {
		serverStat.SessionStatistics = append(serverStat.SessionStatistics, dispatcherStat.SessionStatistics...)
	}

	return serverStat, nil
}

func (srv *QuicSpdyServer) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":http"
	}

	readChanArray := make([](chan UdpData), srv.numOfServers)
	writerArray := make([](*ServerWriter), srv.numOfServers)
	connArray := make([](*net.UDPConn), srv.numOfServers)
	srv.statisticsReq = make([](chan statCallback), srv.numOfServers)
	srv.bufpool = NewBytesBufferPool(1000, 3000) // 3000 = MTU (kMaxPacketSize) * 2

	if srv.ServerConfig == nil {
		srv.ServerConfig = GenerateSerializedServerConfig()
	}

	if srv.Secret == "" {
		srv.Secret = "secret"
	}

	// N consumers
	for i := 0; i < srv.numOfServers; i++ {
		rch := make(chan UdpData, 500)
		wch := make(chan UdpData, 500) // TODO(serialx, hodduc): Optimize buffer size
		statch := make(chan statCallback, 0)

		conn, err := reuseport.NewReusablePortPacketConn("udp4", addr)
		if err != nil {
			return err
		}
		defer conn.Close()

		udp_conn, ok := conn.(*net.UDPConn)
		if !ok {
			return errors.New("ListenPacket did not return net.UDPConn")
		}
		udp_conn.SetReadBuffer(1024 * 1024)  // 1MB
		udp_conn.SetWriteBuffer(1024 * 1024) // 1MB
		connArray[i] = udp_conn

		listen_addr, err := net.ResolveUDPAddr("udp", udp_conn.LocalAddr().String())
		if err != nil {
			return err
		}

		readChanArray[i] = rch
		writerArray[i] = NewServerWriter(wch)
		srv.statisticsReq[i] = statch
		go srv.Serve(listen_addr, writerArray[i], readChanArray[i], srv.statisticsReq[i])
	}

	// N producers
	readFunc := func(conn *net.UDPConn) {
		for {
			buf := srv.bufpool.Get()

			n, peer_addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				// TODO(serialx): Don't panic and keep calm...
				panic(err)
			}

			var connId uint64 = 0
			var parsed bool = false

			if len(buf) > 0 {
				switch buf[0] & 0x8 {
				case 0x8:
					// 8-byte connection id
					if n >= 9 {
						connId = binary.LittleEndian.Uint64(buf[1:9])
						parsed = true
					}
				default: // connection id is omitted
					// TODO(hodduc) Use 4-tuple to identify connection when connId is omitted
					connId = 0
					parsed = true
				}
			}

			if !parsed {
				// Ignore strange packet
				continue
			}

			readChanArray[connId%uint64(srv.numOfServers)] <- UdpData{Addr: peer_addr, Buf: buf, N: n}
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

func (srv *QuicSpdyServer) Serve(listen_addr *net.UDPAddr, writer *ServerWriter, readChan chan UdpData, statChan chan statCallback) error {
	runtime.LockOSThread()

	proofSource := NewProofSource(srv.Certificate)
	cryptoConfig := NewCryptoServerConfig(proofSource, srv.Secret, srv.ServerConfig)
	defer DeleteCryptoServerConfig(cryptoConfig)

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
			dispatcher.ProcessPacket(listen_addr, result.Addr, result.Buf[:result.N])
			srv.bufpool.Put(result.Buf)

		case <-dispatcher.TaskRunner.WaitTimer():
			dispatcher.TaskRunner.DoTasks()
		case fn, ok := <-sessionFnChan:
			if !ok {
				break
			}
			fn()
		case statCallback, ok := <-statChan:
			if !ok {
				break
			}
			stat := dispatcher.Statistics()
			statCallback <- stat
		}
	}
}

// Provide "Alternate-Protocol" header for QUIC
func AltProtoMiddleware(next http.Handler, port int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Alternate-Protocol is deprecated.
		// See https://groups.google.com/a/chromium.org/forum/#!topic/chromium-reviews/aOv41LpPDQY
		w.Header().Add("Alternate-Protocol", fmt.Sprintf("%d:quic", port))
		w.Header().Add("Alt-Svc", fmt.Sprintf("quic=\":%d\"; ma=86400; v=\"36,35,34,33,32,31,30\"", port))
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

	if server, err := NewServer(addr, certFile, keyFile, numOfServers, handler, handler, nil); err != nil {
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

	if server, err := NewServer(addr, certFile, keyFile, numOfServers, handler, nil, nil); err != nil {
		return err
	} else {
		return server.ListenAndServe()
	}
}

func NewServer(addr string, certFile string, keyFile string, numOfServers int, quicHandler http.Handler, nonQuicHandler http.Handler, tlsConfig *tls.Config) (*QuicSpdyServer, error) {
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
			httpServer.TLSConfig = tlsConfig
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
