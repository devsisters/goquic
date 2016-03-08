package goquic

// #cgo CFLAGS: -Iboringssl/
// #cgo CXXFLAGS: -DUSE_OPENSSL=1 -std=gnu++11
// #cgo LDFLAGS: -pthread -lgoquic -lquic -lssl -lcrypto -lstdc++ -lm -lprotobuf
// #cgo darwin LDFLAGS: -framework CoreFoundation -framework Cocoa -framework Security
// #cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/lib/darwin_amd64
// #cgo darwin,386 LDFLAGS: -L${SRCDIR}/lib/darwin_386
// #cgo freebsd,amd64 LDFLAGS: -L${SRCDIR}/lib/freebsd_amd64
// #cgo freebsd,386 LDFLAGS: -L${SRCDIR}/lib/freebsd_386
// #cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib/linux_amd64
// #cgo linux,386 LDFLAGS: -L${SRCDIR}/lib/linux_386
// #include <stddef.h>
// #include "src/adaptor.h"
import "C"

//go:generate python ptr_gen.py ProofSource ProofVerifier ProofVerifyJob TaskRunner ServerWriter ClientWriter QuicDispatcher QuicServerSession GoQuicAlarm QuicServerStream QuicClientStream

func SetLogLevel(level int) {
	C.set_log_level(C.int(level))
}
