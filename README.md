goquic, QUIC support for Go
===========================

This is a work-in-progress QUIC implementation for Go. This is based on
[libquic](https://github.com/devsisters/libquic) library, which is in turn based
on original QUIC implementation on [Chromium](http://www.chromium.org/quic).

QUIC is an experimental protocol aimed at reducing web latency over that of TCP.
On the surface, QUIC is very similar to TCP+TLS+SPDY implemented on UDP. Because
TCP is implement in operating system kernels, and middlebox firmware, making
significant changes to TCP is next to impossible. However, since QUIC is built
on top of UDP, it suffers from no such limitations.

Key features of QUIC over existing TCP+TLS+SPDY include

  * Dramatically reduced connection establishment time
  * Improved congestion control
  * Multiplexing without head of line blocking
  * Forward error correction
  * Connection migration

## Project Status

*This library is highly experimental.* Although `libquic` sources are from
Chromium (which are tested), the Go bindings are still highly pre-alpha state.

Known issues:

  * Stability/Crash issues when under high concurrency:
    * Double free or memory corruption on packet decryption (BoringSSL code)
    * `FATAL:quic_sent_packet_manager.cc(647)] Check failed: packet_retransmitted. No crypto packets found to retransmit.`
    * `ERROR:quic_sent_packet_manager.cc(667)] No retransmittable packets, so RetransmitOldestPacket failed.`
  * No support for read/write streaming. All request/response must fit in
    memory.
  * Secure QUIC not fully tested. May not support all kinds of certificates.

Things to do:

  * Fix crash issues noted above
  * Read/write streaming support

## Preliminary Benchmarks

A very primitive benchmark testing have been done. Testing environments below:

| Optimization | libquic built with `-O3` parameters                       |
| CPU          | Intel(R) Core(TM) i7-4930K CPU @ 3.40GHz                  |
| Server Code  | https://github.com/devsisters/gospdyquic/blob/master/example/server.go |
| Server Parms | `GOMAXPROCS=12 ./server -port 9090 -n 12`                 |
| Client Code  | https://github.com/devsisters/quicbench/blob/master/gobench.go |
| Client Parms | `./gobench -u="https://example.com:9090/" -c 200 -r 1000` |

The server code is modified to create 30B, 1kB, 5kB, 10kB HTTP body payload.
Concurrency is 200 and each thread requests 1,000 requests. It is designed to
measure ideal throughput of the server. Naturally the throughput goes down when
concurrency increases.

Benchmark results:

| Payload Size | Requests per Second |
| ------------ | ------------------- |
| 30B Payload  | 23832.18 RPS        |
| 1kB Payload  | 21704.84 RPS        |
| 5kB Payload  | 9343.58 RPS         |
| 10kB Payload | 5312.75 RPS         |

On 10kB case, calculating the total network throughput is `435Mbps`.

How many connections per second can this server process?

`./gobench -u="https://localhost.devscake.com:9090/" -c 200 -r 100 -qk=false`

Turning off keepalive using `qk` option results in a pure new QUIC connection
per request. The benchmark results are `2905.58 CPS`.


Getting Started
===============

## Build static library files

Although prebuilt static library files already exists in the repository for
convenience, it is always good practice to build library files from source. You
should not trust any unverifiable third-party binaries.

To build the library files for your architecture and OS:

```bash
./build_libs.sh
```

This will fetch `libquic` master and build all the binaries from source. The
C/C++ files for Go bindings will be all built too.

Currently Linux and Mac OS X is supprted.

## How to build

Due to Go 1.4's cgo restrictions, use an environment variable like below to
build your projects. This restriction will be removed from Go 1.5.

```bash
CGO_LDFLAGS="-L$GOPATH/src/github.com/devsisters/goquic/lib/$GOOS_$GOARCH"
```

For example, building gospdyquic example server in Mac:

```bash
CGO_LDFLAGS="-L$GOPATH/src/github.com/devsisters/goquic/lib/darwin_amd64" go build github.com/devsisters/gospdyquic/example
```

## How to use

This is a very low-level QUIC library intended for socket-like use. To use QUIC
as a SPDY transport layer, see
[gospdyquic](https://github.com/devsisters/gospdyquic) for more details.
