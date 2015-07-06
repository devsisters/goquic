#ifndef __GO_PROOF_SOURCE__H__
#define __GO_PROOF_SOURCE__H__
#include "net/quic/crypto/proof_source.h"
#include "net/base/host_port_pair.h"

#include <map>

class GoProofSource : public net::ProofSource {
 public:
  GoProofSource(void* go_proof_source);
  ~GoProofSource() override;

  // ProofSource interface
  bool GetProof(const net::IPAddressNumber& server_ip,
                const std::string& hostname,
                const std::string& server_config,
                bool ecdsa_ok,
                const std::vector<std::string>** out_certs,
                std::string* out_signature) override;

 private:
  void* go_proof_source_;
  std::map<std::string, std::vector<std::string>* > certs_cache_;
  std::vector<std::string> certs_;
  DISALLOW_COPY_AND_ASSIGN(GoProofSource);
};
#endif  // __GO_PROOF_SOURCE__H__
