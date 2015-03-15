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
