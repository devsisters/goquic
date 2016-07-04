package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	_ "net/http/pprof"
	"net/url"
	"os"

	"github.com/devsisters/goquic"
	"github.com/gorilla/handlers"
)

var numOfServers int
var port int
var addr string
var logLevel int
var cert string
var key string
var quicOnly bool
var usesslv3 bool
var serverConfig string

func init() {
	flag.IntVar(&numOfServers, "n", 1, "Number of concurrent quic dispatchers")
	flag.IntVar(&port, "port", 8080, "TCP/UDP port number to listen")
	flag.StringVar(&addr, "addr", "0.0.0.0", "TCP/UDP listen address")
	flag.IntVar(&logLevel, "loglevel", -1, "Log level")
	flag.StringVar(&cert, "cert", "", "Certificate file (PEM), will use encrypted QUIC and TLS when provided")
	flag.StringVar(&key, "key", "", "Private key file (PEM), will use encrypted QUIC and TLS when provided")
	flag.BoolVar(&quicOnly, "quic_only", false, "Use QUIC Only")
	flag.BoolVar(&usesslv3, "use_sslv3", false, "Use SSLv3 on HTTP 1.1. HTTP2 and QUIC are not affected.")
	flag.StringVar(&serverConfig, "scfg", "", "Server config JSON file. If not provided, new one will be generated")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s backend_url\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
}

type PrefixedLogWriter struct {
	prefix []byte
	writer io.Writer
}

func (w PrefixedLogWriter) Write(p []byte) (int, error) {
	if _, err := w.writer.Write(w.prefix); err != nil {
		return 0, err
	}

	return w.writer.Write(p)
}

func main() {
	flag.Parse()
	goquic.SetLogLevel(logLevel)

	if flag.NArg() != 1 {
		flag.Usage()
		return
	}

	proxyUrl := flag.Arg(0)

	log.Printf("About to listen on %s. Go to https://%s:%d/", addr, addr, port)
	addrStr := fmt.Sprintf("%s:%d", addr, port)

	parsedUrl, err := url.Parse(proxyUrl)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Starting reverse proxy for backend URL: %v", parsedUrl)

	var quicHdr, nonQuicHdr http.Handler

	if !quicOnly {
		nonQuicHdr = handlers.CombinedLoggingHandler(PrefixedLogWriter{[]byte("H2 | "), os.Stdout}, httputil.NewSingleHostReverseProxy(parsedUrl))
	}

	quicHdr = handlers.CombinedLoggingHandler(PrefixedLogWriter{[]byte("Q  | "), os.Stdout}, httputil.NewSingleHostReverseProxy(parsedUrl))

	var tlsConfig *tls.Config
	if usesslv3 {
		tlsConfig = &tls.Config{MinVersion: tls.VersionSSL30}
	}

	server, err := goquic.NewServer(addrStr, cert, key, numOfServers, quicHdr, nonQuicHdr, tlsConfig)
	if err != nil {
		log.Fatal(err)
	}

	if len(serverConfig) != 0 {
		if b, err := ioutil.ReadFile(serverConfig); err == nil {
			var cfg *goquic.SerializedServerConfig
			if err := json.Unmarshal(b, &cfg); err != nil {
				log.Printf("Cannot parse %s, new serverConfig will be generated", serverConfig)
			} else {
				server.ServerConfig = cfg
				log.Printf("Successfully parsed %s", serverConfig)
			}
		} else {
			log.Printf("Cannot open %s, new serverConfig will be generated", serverConfig)
		}
	}

	go func() {
		log.Println(http.ListenAndServe("0.0.0.0:6060", nil))
	}()

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
