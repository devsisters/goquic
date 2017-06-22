#include "proof_source_goquic.h"

#include "base/logging.h"

#include "go_functions.h"
#include "net/base/ip_address.h"

namespace net {

ProofSourceGoquic::ProofSourceGoquic(GoPtr go_proof_source)
    : go_proof_source_(go_proof_source) {}

ProofSourceGoquic::~ProofSourceGoquic() {
  ReleaseProofSource_C(go_proof_source_);
}

void ProofSourceGoquic::AddCert(char* cert_c, size_t cert_sz) {
  certs_.push_back(std::string(cert_c, cert_sz));
}

void ProofSourceGoquic::BuildCertChain() {
  chain_ = new ProofSource::Chain(certs_);
}

// ProofSource interface
bool ProofSourceGoquic::GetProof(const net::IPAddress& server_ip,
                             const std::string& hostname,
                             const std::string& server_config,
                             QuicVersion quic_version,
                             base::StringPiece chlo_hash,
                             scoped_refptr<ProofSource::Chain>* out_chain,
                             std::string* out_signature,
                             std::string* out_leaf_cert_sct) {
  char* c_out_signature;
  size_t c_out_signature_sz;

  auto server_ip_bytes = server_ip.bytes();
  auto chlo_hash_str = chlo_hash.as_string();

  int ret = GetProof_C(go_proof_source_,
                       reinterpret_cast<char*>(server_ip_bytes.data()), server_ip_bytes.size(),
                       (char*)hostname.c_str(), (size_t)hostname.length(),
                       (char*)server_config.c_str(), (size_t)server_config.length(),
                       (int)quic_version,
                       (char*)chlo_hash_str.c_str(), (size_t)chlo_hash_str.length(),
                       &c_out_signature, &c_out_signature_sz);

  if (!ret) {
    return false;
  }

  std::string signature(c_out_signature, c_out_signature_sz);
  free(c_out_signature);  // Created from go side

  *out_chain = chain_;
  *out_signature = signature;

  return true;

  //TODO(hodduc): cache?
}

void ProofSourceGoquic::GetProof(const IPAddress& server_ip,
                                   const std::string& hostname,
                                   const std::string& server_config,
                                   QuicVersion quic_version,
                                   base::StringPiece chlo_hash,
                                   std::unique_ptr<Callback> callback) {
  // As a transitional implementation, just call the synchronous version of
  // GetProof, then invoke the callback with the results and destroy it.
  scoped_refptr<ProofSource::Chain> chain;
  std::string signature;
  std::string leaf_cert_sct;
  const bool ok = GetProof(server_ip, hostname, server_config, quic_version,
                           chlo_hash, &chain, &signature, &leaf_cert_sct);
  callback->Run(ok, chain, signature, leaf_cert_sct, nullptr /* details */);
}

}    // namespace net
