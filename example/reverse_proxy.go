package main

import (
	"flag"
	"fmt"
	"log"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/devsisters/goquic"
)

var numOfServers int
var port int
var addr string
var logLevel int
var cert string
var key string
var quicOnly bool

func init() {
	flag.IntVar(&numOfServers, "n", 1, "Number of concurrent quic dispatchers")
	flag.IntVar(&port, "port", 8080, "TCP/UDP port number to listen")
	flag.StringVar(&addr, "addr", "0.0.0.0", "UDP listen address")
	flag.IntVar(&logLevel, "loglevel", -1, "Log level")
	flag.StringVar(&cert, "cert", "", "Certificate file (PEM), will use encrypted QUIC and SSL when provided")
	flag.StringVar(&key, "key", "", "Private key file (PEM), will use encrypted QUIC and SSL when provided")
	flag.BoolVar(&quicOnly, "quic_only", false, "Use Quic Only")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s backend_url\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()
	goquic.SetLogLevel(logLevel)

	if flag.NArg() != 1 {
		flag.Usage()
		return
	}

	proxyUrl := flag.Arg(0)

	log.Printf("About to listen on %d. Go to https://:%d/", addr, port)
	addrStr := fmt.Sprintf("%s:%d", addr, port)

	parsedUrl, err := url.Parse(proxyUrl)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Starting reverse proxy for backend URL: %v", parsedUrl)

	if quicOnly {
		err = goquic.ListenAndServeQuicSpdyOnly(addrStr, cert, key, numOfServers, httputil.NewSingleHostReverseProxy(parsedUrl))
		if err != nil {
			log.Fatal(err)
		}
	} else {
		err = goquic.ListenAndServe(addrStr, cert, key, numOfServers, httputil.NewSingleHostReverseProxy(parsedUrl))
		if err != nil {
			log.Fatal(err)
		}
	}
}
