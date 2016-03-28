package main

import (
	"encoding/json"
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
	flag.StringVar(&serveRoot, "root", "/tmp", "Root of path to serve under https://127.0.0.1/files/")
	flag.IntVar(&logLevel, "loglevel", -1, "Log level")
	flag.StringVar(&cert, "cert", "", "Certificate file (PEM), will use encrypted QUIC and SSL when provided")
	flag.StringVar(&key, "key", "", "Private key file (PEM), will use encrypted QUIC and SSL when provided")
}

func main() {
	flag.Parse()
	goquic.SetLogLevel(logLevel)

	if len(cert) == 0 || len(key) == 0 {
		log.Fatal("QUIC doesn't support non-encrypted mode anymore. Please provide -cert and -key option!")
	}

	log.Printf("About to listen on %d. Go to https://127.0.0.1:%d/", port, port)
	portStr := fmt.Sprintf(":%d", port)

	http.HandleFunc("/", httpHandler)
	http.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir(serveRoot))))

	server, err := goquic.NewServer(portStr, cert, key, numOfServers, http.DefaultServeMux, http.DefaultServeMux, nil)
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/statistics/json", statisticsHandler(server))

	log.Fatal(server.ListenAndServe())
}
