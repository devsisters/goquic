FROM golang:1.7
MAINTAINER Server Team "se@devsisters.com"

RUN apt-get -qq update && apt-get install -y build-essential cmake ninja-build
ADD . /go/src/github.com/devsisters/goquic

WORKDIR /go/src/github.com/devsisters/goquic
RUN ./build_libs.sh -a -r
RUN go build $GOPATH/src/github.com/devsisters/goquic/example/reverse_proxy.go

EXPOSE 8080
EXPOSE 8080/udp

ENTRYPOINT ["/go/src/github.com/devsisters/goquic/reverse_proxy"]
CMD ["--help"]
