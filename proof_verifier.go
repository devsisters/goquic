package goquic

import "C"
import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"log"
	"unsafe"
)

type ProofVerifier struct {
	// Holds Job
	jobs []*ProofVerifyJob
}

type ProofVerifyJob struct {
	hostname     []byte
	serverConfig []byte
	certSct      []byte
	signature    []byte
	certs        [][]byte
}

func CreateProofVerifier() *ProofVerifier {
	return &ProofVerifier{
		jobs: make([]*ProofVerifyJob, 0),
	}
}

var ProofSignatureLabel = []byte{'Q', 'U', 'I', 'C', ' ', 's', 'e', 'r', 'v', 'e', 'r', ' ', 'c', 'o', 'n', 'f', 'i', 'g', ' ', 's', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', 0x00}

func (job *ProofVerifyJob) CheckSignature(cert *x509.Certificate) error {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		// cert.CheckSignature() uses PKCS1v15, not PSS. So we cannot use that on RSA
		h := sha256.New()
		h.Write(ProofSignatureLabel)
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
func NewProofVerifyJob(proof_verifier_c unsafe.Pointer,
	hostname_c unsafe.Pointer, hostname_sz C.size_t,
	server_config_c unsafe.Pointer, server_config_sz C.size_t,
	cert_sct_c unsafe.Pointer, cert_sct_sz C.size_t,
	signature_c unsafe.Pointer, signature_sz C.size_t) unsafe.Pointer {

	proofVerifier := (*ProofVerifier)(proof_verifier_c)

	job := &ProofVerifyJob{
		hostname:     C.GoBytes(hostname_c, C.int(hostname_sz)),
		serverConfig: C.GoBytes(server_config_c, C.int(server_config_sz)),
		certSct:      C.GoBytes(cert_sct_c, C.int(cert_sct_sz)),
		signature:    C.GoBytes(signature_c, C.int(signature_sz)),
		certs:        make([][]byte, 0),
	}
	proofVerifier.jobs = append(proofVerifier.jobs, job)

	return unsafe.Pointer(job)
}

//export ProofVerifyJobAddCert
func ProofVerifyJobAddCert(job_c unsafe.Pointer, cert_c unsafe.Pointer, cert_sz C.size_t) {
	job := (*ProofVerifyJob)(job_c)
	job.certs = append(job.certs, C.GoBytes(cert_c, C.int(cert_sz)))
}

//export ProofVerifyJobVerifyProof
func ProofVerifyJobVerifyProof(job_c unsafe.Pointer) C.int {
	job := (*ProofVerifyJob)(job_c)

	if ret := job.Verify(); ret {
		return C.int(1)
	} else {
		return C.int(0)
	}
}
