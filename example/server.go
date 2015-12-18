package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/devsisters/goquic"
)

var numOfServers int
var port int
var serveRoot string
var logLevel int
var cert string
var key string

func httpHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Trailer", "AtEnd1, AtEnd2")
	w.Header().Add("Trailer", "AtEnd3")

	w.Header().Set("Content-Type", "text/plain; charset=utf-8") // normal header
	w.WriteHeader(http.StatusOK)

	w.Header().Set("AtEnd1", "value 1")
	io.WriteString(w, "This HTTP response has both headers before this text and trailers at the end.\n")
	w.Header().Set("AtEnd2", "value 2")
	w.Header().Set("AtEnd3", "value 3") // These will appear as trailers.
}

func init() {
	flag.IntVar(&numOfServers, "n", 1, "Number of concurrent quic dispatchers")
	flag.IntVar(&port, "port", 8080, "TCP/UDP port number to listen")
	flag.StringVar(&serveRoot, "root", "/tmp", "Root of path to serve under https://127.0.0.1/files/")
	flag.IntVar(&logLevel, "loglevel", -1, "Log level")
	flag.StringVar(&cert, "cert", "", "Certificate file (PEM), will use encrypted QUIC and SSL when provided")
	flag.StringVar(&key, "key", "", "Private key file (PEM), will use encrypted QUIC and SSL when provided")
}

func main() {
	flag.Parse()
	goquic.SetLogLevel(logLevel)

	useEncryption := false
	if len(cert) > 0 && len(key) > 0 {
		useEncryption = true
	}

	scheme := "http"
	if useEncryption {
		scheme = "https"
	}
	log.Printf("About to listen on %d. Go to %s://127.0.0.1:%d/", port, scheme, port)
	portStr := fmt.Sprintf(":%d", port)

	http.HandleFunc("/", httpHandler)
	http.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir(serveRoot))))

	var err error

	if useEncryption {
		err = goquic.ListenAndServeSecure(portStr, cert, key, numOfServers, nil)
	} else {
		err = goquic.ListenAndServe(portStr, numOfServers, nil)
	}

	if err != nil {
		log.Fatal(err)
	}
}
