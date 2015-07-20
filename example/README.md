SPDY/QUIC enabled server/client written in Go
=============================================

We currently have [server](server.go), [client](client.go),
and [reverse proxy](reverse_proxy.go) implementation.


## How to build

Due to Go 1.4's cgo restrictions, use an environment variable like below to
build your projects. This restriction will be removed from Go 1.5.

```bash
CGO_CFLAGS="-I$GOPATH/src/github.com/devsisters/goquic/libquic/boringssl/include"
CGO_LDFLAGS="-L$GOPATH/src/github.com/devsisters/goquic/lib/$GOOS_$GOARCH"

go build $GOPATH/src/github.com/devsisters/goquic/example/server.go
go build $GOPATH/src/github.com/devsisters/goquic/example/client.go
go build $GOPATH/src/github.com/devsisters/goquic/example/reverse_proxy.go
```

For example, building goquic example server in Mac:

```bash
CGO_CFLAGS="-I$GOPATH/src/github.com/devsisters/goquic/libquic/boringssl/include" \
CGO_LDFLAGS="-L$GOPATH/src/github.com/devsisters/goquic/lib/darwin_amd64" \
go build $GOPATH/src/github.com/devsisters/goquic/example/server.go
```

In Linux:

```bash
CGO_CFLAGS="-I$GOPATH/src/github.com/devsisters/goquic/libquic/boringssl/include" \
CGO_LDFLAGS="-L$GOPATH/src/github.com/devsisters/goquic/lib/linux_amd64" \
go build $GOPATH/src/github.com/devsisters/goquic/example/server.go
```
