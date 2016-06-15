package goquic

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

type QuicRoundTripper struct {
	conns          map[string]*Conn
	connsLock      *sync.RWMutex
	keepConnection bool
}

type badStringError struct {
	what string
	str  string
}

func NewRoundTripper(keepConnection bool) *QuicRoundTripper {
	return &QuicRoundTripper{
		conns:          make(map[string]*Conn),
		connsLock:      &sync.RWMutex{},
		keepConnection: keepConnection,
	}
}

func (e *badStringError) Error() string { return fmt.Sprintf("%s %q", e.what, e.str) }

// from golang: net/http/client.go
func hasPort(s string) bool { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }

// from golang: net/http/transport.go
var portMap = map[string]string{
	"http":  "80",
	"https": "443",
}

func (q *QuicRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != "GET" && request.Method != "POST" {
		return nil, errors.New("non-GET/POST request is not supported yet. Sorry.")
		// TODO(hodduc): HEAD / PUT support
	}

	var conn *Conn
	var exists bool

	hostname := request.URL.Host
	if !hasPort(hostname) {
		hostname = hostname + ":" + portMap[request.URL.Scheme]
	}

	q.connsLock.RLock()
	conn, exists = q.conns[hostname]
	q.connsLock.RUnlock()
	if !q.keepConnection || !exists {
		conn_new, err := Dial("udp4", hostname)
		if err != nil {
			fmt.Println("error occured!", err)
			return nil, err
		}

		q.connsLock.Lock()
		q.conns[hostname] = conn_new
		q.connsLock.Unlock()

		conn = conn_new
	}

	conn.Lock()
	defer conn.Unlock()
	st := conn.CreateStream()

	header := make(http.Header)
	for k, v := range request.Header {
		for _, vv := range v {
			header.Add(k, vv)
		}
	}
	header.Set(":authority", hostname)
	header.Set(":method", request.Method)
	header.Set(":path", request.URL.RequestURI())
	header.Set(":scheme", request.URL.Scheme)

	if request.Method == "GET" {
		st.WriteHeader(header, true)
	} else if request.Method == "POST" {
		st.WriteHeader(header, false)

		body, err := ioutil.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}

		if _, err := st.Write(body); err != nil {
			return nil, err
		}

		if err := st.FinWrite(); err != nil {
			return nil, err
		}
	}

	recvHeader, err := st.Header()
	if err != nil {
		return nil, err
	}

	resp := &http.Response{}
	resp.Status = recvHeader.Get(":status")
	f := strings.SplitN(resp.Status, " ", 3)
	if len(f) < 1 {
		return nil, &badStringError{"malformed HTTP response", resp.Status}
	}
	resp.StatusCode, err = strconv.Atoi(f[0])
	if err != nil {
		return nil, &badStringError{"malformed HTTP status code", f[0]}
	}

	resp.ProtoMajor, resp.ProtoMinor = 2, 0

	resp.Header = recvHeader

	resp.ContentLength, err = strconv.ParseInt(recvHeader.Get("content-length"), 10, 64)
	if err != nil {
		resp.ContentLength = -1
	}
	resp.Request = request

	if q.keepConnection {
		resp.Body = ioutil.NopCloser(st)
	} else {
		// XXX(hodduc): "conn" should be closed after the user reads all response body, so
		// it's hard to determine when to close "conn". So we read all response body prematurely.
		// If response is very big, this could be problematic. (Consider using runtime.finalizer())
		body, err := ioutil.ReadAll(st)
		if err != nil {
			return nil, err
		}
		resp.Body = ioutil.NopCloser(bytes.NewBuffer(body))

		resp.Trailer = st.Trailer()

		conn.Close()
	}

	return resp, nil
}
