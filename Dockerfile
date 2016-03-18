FROM golang
MAINTAINER Server Team "se@devsisters.com"

RUN apt-get -qq update && apt-get install -y build-essential cmake ninja-build
ADD . /go/src/github.com/devsisters/goquic

WORKDIR /go/src/github.com/devsisters/goquic
RUN GOQUIC_BUILD=Release ./build_libs.sh
RUN go get github.com/bradfitz/http2 github.com/oleiade/lane github.com/vanillahsu/go_reuseport github.com/gorilla/handlers
RUN go build $GOPATH/src/github.com/devsisters/goquic/example/reverse_proxy.go

EXPOSE 8080
EXPOSE 8080/udp

ENTRYPOINT ["/go/src/github.com/devsisters/goquic/reverse_proxy"]
CMD ["--help"]
