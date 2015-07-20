SPDY/QUIC enabled server/client written in Go
=============================================

This is a work-in-progress SPDY/QUIC implementation for Go. This is based on
[goquic](https://github.com/devsisters/goquic) library. You can use this library
to add SPDY/QUIC support for your existing Go HTTP server.

## How to build

Due to Go 1.4's cgo restrictions, use an environment variable like below to
build your projects. This restriction will be removed from Go 1.5.

```bash
CGO_CFLAGS="-I$GOPATH/src/github.com/devsisters/goquic/libquic/boringssl/include"
CGO_LDFLAGS="-L$GOPATH/src/github.com/devsisters/goquic/lib/$GOOS_$GOARCH"
```

For example, building goquic example server in Mac:

```bash
CGO_CFLAGS="-I$GOPATH/src/github.com/devsisters/goquic/libquic/boringssl/include" CGO_LDFLAGS="-L$GOPATH/src/github.com/devsisters/goquic/lib/darwin_amd64" go build $GOPATH/github.com/devsisters/goquic/example/server.go
```

In Linux:

```bash
CGO_CFLAGS="-I$GOPATH/src/github.com/devsisters/goquic/libquic/boringssl/include" CGO_LDFLAGS="-L$GOPATH/src/github.com/devsisters/goquic/lib/linux_amd64" go build $GOPATH/github.com/devsisters/goquic/example/server.go
```

## How to use server

When running a HTTP server, do:

```go
goquic.ListenAndServe(":8080", 1, nil)
```

instead of

```go
http.ListenAndServe(":8080", nil)
```

## How to use client

You need to create http.Client with Transport changed, do:

```go
client := &http.Client{
	Transport: goquic.NewRoundTripper(false),
}
resp, err := client.Get("http://example.com/")
```

instead of

```go
resp, err := http.Get("http://example.com/")
```
