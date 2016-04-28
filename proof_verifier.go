package goquic

import "C"
import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"log"
	"unsafe"
)

type ProofVerifier struct {
	// Holds Job
	jobs []*ProofVerifyJob
}

type ProofVerifyJob struct {
	quicVersion int

	hostname     []byte
	serverConfig []byte
	chloHash     []byte
	certSct      []byte
	signature    []byte
	certs        [][]byte
}

func CreateProofVerifier() *ProofVerifier {
	return &ProofVerifier{
		jobs: make([]*ProofVerifyJob, 0),
	}
}

// Generate "proof of authenticity" (See "Quic Crypto" docs for details)
// Length of the prefix used to calculate the signature: length of label + 0x00 byte
var ProofSignatureLabelOld = []byte{'Q', 'U', 'I', 'C', ' ', 's', 'e', 'r', 'v', 'e', 'r', ' ', 'c', 'o', 'n', 'f', 'i', 'g', ' ', 's', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', 0x00}
var ProofSignatureLabel = []byte{'Q', 'U', 'I', 'C', ' ', 'C', 'H', 'L', 'O', ' ', 'a', 'n', 'd', ' ', 's', 'e', 'r', 'v', 'e', 'r', ' ', 'c', 'o', 'n', 'f', 'i', 'g', ' ', 's', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', 0x00}

func (job *ProofVerifyJob) CheckSignature(cert *x509.Certificate) error {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		// cert.CheckSignature() uses PKCS1v15, not PSS. So we cannot use that on RSA
		h := sha256.New()

		if job.quicVersion > 30 {
			h.Write(ProofSignatureLabel)

			bs := make([]byte, 4)
			binary.LittleEndian.PutUint32(bs, uint32(len(job.chloHash)))
			h.Write(bs)
			h.Write(job.chloHash)
		} else {
			h.Write(ProofSignatureLabelOld)
		}
		h.Write(job.serverConfig)

		if err := rsa.VerifyPSS(pub, crypto.SHA256, h.Sum(nil), job.signature, nil); err != nil {
			return err
		}

	case *ecdsa.PublicKey:
		// TODO(hodduc): TEST needed
		if err := cert.CheckSignature(x509.ECDSAWithSHA256, job.serverConfig, job.signature); err != nil {
			return err
		}

	default:
		return errors.New("Unsupported Public key type")
	}

	return nil
}

func (job *ProofVerifyJob) Verify() bool {
	leafcert, err := x509.ParseCertificate(job.certs[0])
	if err != nil {
		// TODO(hodduc) error chk, log chk
		log.Fatal("Parsing leaf cert", err)
		return false
	}

	if err := job.CheckSignature(leafcert); err != nil {
		// TODO(hodduc) error chk, log chk
		log.Fatal("Signature fail", err)
		return false
	}

	buf := bytes.NewBuffer(nil)
	for _, asn1cert := range job.certs {
		buf.Write(asn1cert)
	}

	certs, err := x509.ParseCertificates(buf.Bytes())
	if err != nil {
		// TODO(hodduc) error chk, log chk
		log.Fatal("Parsing cert chain", err)
		return false
	}

	intmPool := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intmPool.AddCert(certs[i])
	}

	verifyOpt := x509.VerifyOptions{
		DNSName:       string(job.hostname),
		Intermediates: intmPool,
	}
	if _, err := certs[0].Verify(verifyOpt); err != nil {
		log.Fatal("Verify failed", err)
		return false
	}
	return true
}

//export NewProofVerifyJob
func NewProofVerifyJob(proof_verifier_key int64, quicVersion int,
	hostname_c unsafe.Pointer, hostname_sz C.size_t,
	server_config_c unsafe.Pointer, server_config_sz C.size_t,
	chlo_hash_c unsafe.Pointer, chlo_hash_sz C.size_t,
	cert_sct_c unsafe.Pointer, cert_sct_sz C.size_t,
	signature_c unsafe.Pointer, signature_sz C.size_t) int64 {

	proofVerifier := proofVerifierPtr.Get(proof_verifier_key)

	job := &ProofVerifyJob{
		quicVersion:  quicVersion,
		hostname:     C.GoBytes(hostname_c, C.int(hostname_sz)),
		serverConfig: C.GoBytes(server_config_c, C.int(server_config_sz)),
		chloHash:     C.GoBytes(chlo_hash_c, C.int(chlo_hash_sz)),
		certSct:      C.GoBytes(cert_sct_c, C.int(cert_sct_sz)),
		signature:    C.GoBytes(signature_c, C.int(signature_sz)),
		certs:        make([][]byte, 0),
	}
	proofVerifier.jobs = append(proofVerifier.jobs, job)

	return proofVerifyJobPtr.Set(job)
}

//export ProofVerifyJobAddCert
func ProofVerifyJobAddCert(job_key int64, cert_c unsafe.Pointer, cert_sz C.size_t) {
	job := proofVerifyJobPtr.Get(job_key)
	job.certs = append(job.certs, C.GoBytes(cert_c, C.int(cert_sz)))
}

//export ProofVerifyJobVerifyProof
func ProofVerifyJobVerifyProof(job_key int64) C.int {
	job := proofVerifyJobPtr.Get(job_key)

	// XXX(hodduc): Job has ended, so I will release job here. Job should not be referenced again
	defer proofVerifyJobPtr.Del(job_key)

	if ret := job.Verify(); ret {
		return C.int(1)
	} else {
		return C.int(0)
	}

}

//export ReleaseProofVerifier
func ReleaseProofVerifier(proof_verifier_key int64) {
	proofVerifierPtr.Del(proof_verifier_key)
}
