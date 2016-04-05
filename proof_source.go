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
	"crypto/tls"
	"crypto/x509"
	"net"
	"unsafe"
)

// Generate "proof of authenticity" (See "Quic Crypto" docs for details)
// Length of the prefix used to calculate the signature: length of label + 0x00 byte
const kPrefixStr = "QUIC server config signature"
const kPrefixLen = len(kPrefixStr) + 1

type ProofSource struct {
	Certificate   tls.Certificate
	proofSource_c unsafe.Pointer
}

func (ps *ProofSource) GetProof(addr net.IP, hostname []byte, serverConfig []byte, ecdsaOk bool) (outSignature []byte) {
	var err error = nil

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

	switch priv := ps.Certificate.PrivateKey.(type) {
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
	return outSignature
}

func NewProofSource(cert tls.Certificate) *ProofSource {
	ps := &ProofSource{Certificate: cert}

	// Initialize Proof Source
	proofSource_c := C.init_proof_source_goquic(C.GoPtr(proofSourcePtr.Set(ps)))

	for _, cert := range cert.Certificate {
		x509cert, err := x509.ParseCertificate(cert)
		if err != nil {
			panic(err)
		}
		C.proof_source_goquic_add_cert(proofSource_c, (*C.char)(unsafe.Pointer(&x509cert.Raw[0])), C.size_t(len(x509cert.Raw)))
	}

	C.proof_source_goquic_build_cert_chain(proofSource_c)

	ps.proofSource_c = proofSource_c

	return ps
}

//export GetProof
func GetProof(proof_source_key int64, server_ip_c unsafe.Pointer, server_ip_sz C.size_t, hostname_c unsafe.Pointer, hostname_sz_c C.size_t, server_config_c unsafe.Pointer, server_config_sz_c C.size_t, ecdsa_ok_c C.int, out_signature_c **C.char, out_signature_sz_c *C.size_t) C.int {
	proofSource := proofSourcePtr.Get(proof_source_key)

	serverIp := net.IP(C.GoBytes(server_ip_c, C.int(server_ip_sz)))
	hostname := C.GoBytes(hostname_c, C.int(hostname_sz_c))
	serverConfig := C.GoBytes(server_config_c, C.int(server_config_sz_c))
	ecdsaOk := int(ecdsa_ok_c) > 0

	sig := proofSource.GetProof(serverIp, hostname, serverConfig, ecdsaOk)

	*out_signature_c = C.CString(string(sig)) // Must free C string
	*out_signature_sz_c = C.size_t(len(sig))

	return C.int(1)
}

//export ReleaseProofSource
func ReleaseProofSource(proof_source_key int64) {
	proofSourcePtr.Del(proof_source_key)
}
