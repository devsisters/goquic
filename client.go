package goquic

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

type QuicRoundTripper struct {
	conns          map[string]*Conn
	keepConnection bool
}

type badStringError struct {
	what string
	str  string
}

func NewRoundTripper(keepConnection bool) *QuicRoundTripper {
	return &QuicRoundTripper{
		conns:          make(map[string]*Conn),
		keepConnection: keepConnection,
	}
}

func (e *badStringError) Error() string { return fmt.Sprintf("%s %q", e.what, e.str) }

func (q *QuicRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != "GET" {
		return nil, errors.New("non-GET request is not supported yet. Sorry.")
		// TODO(hodduc): POST / HEAD / PUT support
	}

	var conn *Conn
	var exists bool

	conn, exists = q.conns[request.Host]
	if !q.keepConnection || !exists {
		conn_new, err := Dial("udp4", request.Host)
		if err != nil {
			return nil, err
		}

		q.conns[request.Host] = conn_new
		conn = conn_new
	}
	st := conn.CreateStream()

	header := make(http.Header)
	for k, v := range request.Header {
		for _, vv := range v {
			header.Add(k, vv)
		}
	}
	header.Set(":host", request.Host)
	header.Set(":version", request.Proto)
	header.Set(":method", request.Method)
	header.Set(":path", request.URL.RequestURI())
	header.Set(":scheme", request.URL.Scheme)

	if request.Method == "GET" {
		st.WriteHeader(header, true)
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
		conn.Close()
	}

	return resp, nil
}
