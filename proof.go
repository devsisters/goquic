package goquic

// #include <stddef.h>
// #include "src/adaptor.h"
import "C"
import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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

type ServerProofSource struct {
	server *QuicSpdyServer
}

func (ps *ServerProofSource) IsSecure() bool {
	return ps.server.isSecure
}

func (ps *ServerProofSource) GetProof(addr net.IP, hostname []byte, serverConfig []byte, ecdsaOk bool) (outCerts [][]byte, outSignature []byte) {
	outCerts = make([][]byte, 0, 10)
	for _, cert := range ps.server.Certificate.Certificate {
		x509cert, err := x509.ParseCertificate(cert)
		if err != nil {
			panic(err)
		}
		outCerts = append(outCerts, x509cert.Raw)
	}
	var err error = nil

	// Generate "proof of authenticity" (See "Quic Crypto" docs for details)
	// Length of the prefix used to calculate the signature: length of label + 0x00 byte
	const kPrefixStr = "QUIC server config signature"
	const kPrefixLen = len(kPrefixStr) + 1
	//bufferToSign := make([]byte, 0, len(serverConfig)+kPrefixLen)
	bufferToSign := bytes.NewBuffer(make([]byte, 0, len(serverConfig)+kPrefixLen))
	bufferToSign.Write([]byte(kPrefixStr))
	bufferToSign.Write([]byte("\x00"))
	bufferToSign.Write(serverConfig)

	hasher := crypto.SHA256.New()
	_, err = hasher.Write(bufferToSign.Bytes())
	if err != nil {
		panic("Error while hashing")
	}
	hashSum := hasher.Sum(nil)

	switch priv := ps.server.Certificate.PrivateKey.(type) {
	case *rsa.PrivateKey:
		outSignature, err = priv.Sign(rand.Reader, hashSum, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
		if err != nil {
			panic(err)
		}
	case *ecdsa.PrivateKey:
		// XXX(serialx): Not tested. Should input be a hashSum or the original message?
		//               Since there is no secure QUIC server reference implementation,
		//               only a real test with the Chrome browser would verify the code.
		//               Since I don't currently have a ECDSA certificate, no testing is done.
		outSignature, err = priv.Sign(rand.Reader, hashSum, nil)
		if err != nil {
			panic(err)
		}
	default:
		panic("Unknown form of private key")
	}
	if err != nil {
		panic(err)
	}
	return outCerts, outSignature
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
