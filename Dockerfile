FROM golang:1.6.2
MAINTAINER Server Team "se@devsisters.com"

RUN apt-get -qq update && apt-get install -y build-essential cmake ninja-build
ADD . /go/src/github.com/devsisters/goquic

WORKDIR /go/src/github.com/devsisters/goquic
RUN ./build_libs.sh -a -r
RUN go get github.com/oleiade/lane github.com/vanillahsu/go_reuseport github.com/gorilla/handlers golang.org/x/net/http2
RUN go build $GOPATH/src/github.com/devsisters/goquic/example/reverse_proxy.go

EXPOSE 8080
EXPOSE 8080/udp

ENTRYPOINT ["/go/src/github.com/devsisters/goquic/reverse_proxy"]
CMD ["--help"]
