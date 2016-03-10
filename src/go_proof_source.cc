#include "go_proof_source.h"

#include "base/logging.h"

#include "go_functions.h"
#include "net/base/ip_address.h"

namespace net {

GoProofSource::GoProofSource(GoPtr go_proof_source)
    : go_proof_source_(go_proof_source) {}

GoProofSource::~GoProofSource() {
  ReleaseProofSource_C(go_proof_source_);
}

// ProofSource interface
bool GoProofSource::GetProof(const net::IPAddress& server_ip,
                             const std::string& hostname,
                             const std::string& server_config,
                             bool ecdsa_ok,
                             scoped_refptr<ProofSource::Chain>* out_chain,
                             std::string* out_signature,
                             std::string* out_leaf_cert_sct) {
  char** c_certs;
  int c_certs_sz;
  char* c_out_signature;
  size_t* c_certs_item_sz;
  size_t c_out_signature_sz;

  auto server_ip_bytes = server_ip.bytes();

  int ret = GetProof_C(go_proof_source_, reinterpret_cast<char*>(server_ip_bytes.data()),
                       server_ip_bytes.size(), (char*)hostname.c_str(),
                       (size_t)hostname.length(), (char*)server_config.c_str(),
                       (size_t)server_config.length(), ecdsa_ok, &c_certs,
                       &c_certs_sz, &c_certs_item_sz, &c_out_signature,
                       &c_out_signature_sz);
  if (!ret) {
    return false;
  }

  std::vector<std::string> certs;
  for (int i = 0; i < c_certs_sz; i++) {
    certs.push_back(std::string(c_certs[i], c_certs_item_sz[i]));
    free(c_certs[i]);  // Created from go side
  }

  /*
  // XXX(serialx): certs_cache_ only keeps growing. And we don't actually use it
  for cache. :(
  // XXX(hodduc): this code is not thread-safe. should be locked when this
  snippet is uncommented
  //
  auto it = certs_cache_.find(hostname);
  if (it != certs_cache_.end()) {
      certs_cache_.erase(it);  // Erase former allocated vector
      delete it->second;
  }
  certs_cache_[hostname] = certs;
  */

  std::string signature(c_out_signature, c_out_signature_sz);
  free(c_out_signature);  // Created from go side

  chain_ = new ProofSource::Chain(certs);


  *out_chain = chain_;
  *out_signature = signature;
  return true;
}

}    // namespace net
