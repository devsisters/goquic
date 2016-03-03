#ifndef __GO_PROOF_SOURCE__H__
#define __GO_PROOF_SOURCE__H__

#include <map>

#include "net/quic/crypto/proof_source.h"
#include "net/base/host_port_pair.h"
#include "go_structs.h"

// This should be thread-safe, because multiple dispatcher may concurrently call
// GetProof()
class GoProofSource : public net::ProofSource {
 public:
  GoProofSource(GoPtr go_proof_source);
  ~GoProofSource() override;

  // ProofSource interface
  bool GetProof(const net::IPAddressNumber& server_ip,
                const std::string& hostname,
                const std::string& server_config,
                bool ecdsa_ok,
                const std::vector<std::string>** out_certs,
                std::string* out_signature,
                std::string* out_leaf_cert_sct) override;

 private:
  GoPtr go_proof_source_;
  std::map<std::string, std::vector<std::string>*> certs_cache_;
  std::vector<std::string> certs_;
  DISALLOW_COPY_AND_ASSIGN(GoProofSource);
};
#endif  // __GO_PROOF_SOURCE__H__
