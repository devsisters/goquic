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
	// Implementor should be thread-safe
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
	cryptoConfig_c := C.init_crypto_config(C.GoPtr(proofSourcePtr.Set(proofSource)))
	return &ServerCryptoConfig{cryptoConfig_c}
}

//export GetProof
func GetProof(proof_source_key int64, server_ip_c unsafe.Pointer, server_ip_sz C.size_t, hostname_c unsafe.Pointer, hostname_sz_c C.size_t, server_config_c unsafe.Pointer, server_config_sz_c C.size_t, ecdsa_ok_c C.int, out_certs_c ***C.char, out_certs_sz_c *C.int, out_certs_item_sz_c **C.size_t, out_signature_c **C.char, out_signature_sz_c *C.size_t) C.int {
	proofSource := proofSourcePtr.Get(proof_source_key)
	if !proofSource.impl.IsSecure() {
		return C.int(0)
	}

	serverIp := net.IP(C.GoBytes(server_ip_c, C.int(server_ip_sz)))
	hostname := C.GoBytes(hostname_c, C.int(hostname_sz_c))
	serverConfig := C.GoBytes(server_config_c, C.int(server_config_sz_c))
	ecdsaOk := int(ecdsa_ok_c) > 0

	certs, sig := proofSource.impl.GetProof(serverIp, hostname, serverConfig, ecdsaOk)
	certsCStrList := make([](*C.char), 0, 10)
	certsCStrSzList := make([](C.size_t), 0, 10)

	// XXX(hodduc): certsCStrList and certsCStrSzList may be garbage collected before reading in C side, isn't it?

	for _, outCert := range certs {
		outCert_c := C.CString(string(outCert)) // Must free this C string in C code
		certsCStrList = append(certsCStrList, outCert_c)
		certsCStrSzList = append(certsCStrSzList, C.size_t(len(outCert)))
	}

	*out_certs_c = (**C.char)(unsafe.Pointer(&certsCStrList[0]))
	*out_certs_sz_c = C.int(len(certsCStrList))
	*out_certs_item_sz_c = (*C.size_t)(unsafe.Pointer(&certsCStrSzList[0]))
	*out_signature_c = C.CString(string(sig)) // Must free C string
	*out_signature_sz_c = C.size_t(len(sig))

	return C.int(1)
}

//export ReleaseProofSource
func ReleaseProofSource(proof_source_key int64) {
	proofSourcePtr.Del(proof_source_key)
}
