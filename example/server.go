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
	"strconv"

	"github.com/devsisters/goquic"
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
var serveRoot string

func httpHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Trailer", "AtEnd1, AtEnd2")
	w.Header().Add("Trailer", "AtEnd3")

	w.Header().Set("Content-Type", "text/html; charset=utf-8") // normal header
	w.WriteHeader(http.StatusOK)

	w.Header().Set("AtEnd1", "value 1")
	io.WriteString(w, "This HTTP response has both headers before this text and trailers at the end.<br/>")
	io.WriteString(w, "<a href='/numbers'>Numbers test (0~9999)</a><br/>")
	io.WriteString(w, "<a href='/files'>Files</a><br/>")
	io.WriteString(w, req.RemoteAddr)
	io.WriteString(w, "\n")
	w.Header().Set("AtEnd2", "value 2")
	w.Header().Set("AtEnd3", "value 3") // These will appear as trailers.
}

func numbersHandler(w http.ResponseWriter, req *http.Request) {
	for i := 0; i < 10000; i++ {
		io.WriteString(w, strconv.Itoa(i))
		io.WriteString(w, "\n")
	}
}

func statisticsHandler(server *goquic.QuicSpdyServer) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		stat, err := server.Statistics()
		if err != nil {
			http.Error(w, "cannot load statistics", http.StatusInternalServerError)
			return
		}

		r, err := json.Marshal(stat)
		if err != nil {
			http.Error(w, "cannot marshal stat objects", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(r)
	}
}

func init() {
	flag.IntVar(&numOfServers, "n", 1, "Number of concurrent quic dispatchers")
	flag.IntVar(&port, "port", 8080, "TCP/UDP port number to listen")
	flag.StringVar(&addr, "addr", "0.0.0.0", "TCP/UDP listen address")
	flag.IntVar(&logLevel, "loglevel", -1, "Log level")
	flag.StringVar(&cert, "cert", "", "Certificate file (PEM), will use encrypted QUIC and SSL when provided")
	flag.StringVar(&key, "key", "", "Private key file (PEM), will use encrypted QUIC and SSL when provided")
	flag.BoolVar(&quicOnly, "quic_only", false, "Use QUIC Only")
	flag.BoolVar(&usesslv3, "use_sslv3", false, "Use SSLv3 on HTTP 1.1. HTTP2 and QUIC are not affected.")
	flag.StringVar(&serverConfig, "scfg", "", "Server config JSON file. If not provided, new one will be generated")

	flag.StringVar(&serveRoot, "root", "/tmp", "Root of path to serve under https://127.0.0.1/files/")
}

func main() {
	flag.Parse()
	goquic.SetLogLevel(logLevel)

	if len(cert) == 0 || len(key) == 0 {
		log.Fatal("QUIC doesn't support non-encrypted mode anymore. Please provide -cert and -key option!")
	}

	log.Printf("About to listen on %s. Go to https://%s:%d/", addr, addr, port)
	addrStr := fmt.Sprintf("%s:%d", addr, port)

	http.HandleFunc("/", httpHandler)
	http.HandleFunc("/numbers", numbersHandler)
	http.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir(serveRoot))))

	var tlsConfig *tls.Config
	if usesslv3 {
		tlsConfig = &tls.Config{MinVersion: tls.VersionSSL30}
	}

	var quicHdr, nonQuicHdr http.Handler

	if !quicOnly {
		nonQuicHdr = http.DefaultServeMux
	}

	quicHdr = http.DefaultServeMux

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

	http.Handle("/statistics/json", statisticsHandler(server))

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
