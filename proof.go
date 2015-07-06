package goquic

// #include <stddef.h>
// #include "src/adaptor.h"
import "C"
import (
	"net"
	"unsafe"
)

type ProofSource struct {
	impl ProofSourceImpl
}

type ProofSourceImpl interface {
	GetProof(addr net.IP, hostname []byte, serverConfig []byte, ecdsaOk bool) (outCerts [][]byte, outSignature []byte)
	IsSecure() bool
}

type ServerCryptoConfig struct {
	serverCryptoConfig unsafe.Pointer
}

func NewProofSource(impl ProofSourceImpl) *ProofSource {
	return &ProofSource{impl}
}

func InitCryptoConfig(proofSource *ProofSource) *ServerCryptoConfig {
	cryptoConfig_c := C.init_crypto_config(unsafe.Pointer(proofSource))
	return &ServerCryptoConfig{cryptoConfig_c}
}
