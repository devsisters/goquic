package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"

	"github.com/devsisters/goquic"
)

var host string
var logLevel int

func init() {
	flag.StringVar(&host, "host", "127.0.0.1:8080", "host to connect")
	flag.IntVar(&logLevel, "loglevel", -1, "Log level")
}

func main() {
	goquic.Initialize()
	goquic.SetLogLevel(logLevel)

	flag.Parse()

	conn, err := goquic.Dial("udp4", host)
	if err != nil {
		panic(err)
	}

	fmt.Println("Connect complete!", conn)

	st := conn.CreateStream()
	fmt.Println("CreateStream complete!", st)
	header := make(http.Header)
	header.Set(":host", "172.24.0.216:8080")
	header.Set(":version", "HTTP/1.0")
	header.Set(":method", "GET")
	header.Set(":path", "/")
	header.Set(":scheme", "http")
	st.WriteHeader(header, false)
	st.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	st.FinWrite()

	recvHeader, err := st.ReadHeader()
	if err != nil {
		panic(err)
	}
	fmt.Println("Header:", recvHeader)

	buf := make([]byte, 4096)
	n, err := st.Read(buf)
	if err != nil {
		panic(err)
	}
	fmt.Println("Response:", string(buf[:n]))

	n, err = st.Read(buf)
	if err == io.EOF {
		fmt.Println("Received EOF")
	} else if err != nil {
		panic(err)
	} else {
		fmt.Println("Response:", string(buf[:n]))
	}
}
