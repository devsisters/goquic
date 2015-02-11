#ifndef __GO_PROOF_SOURCE__H__
#define __GO_PROOF_SOURCE__H__
#include "net/quic/crypto/proof_source.h"

#include <map>

class GoProofSource : public net::ProofSource {
 public:
  GoProofSource(void* go_quic_dispatcher);
  ~GoProofSource() override;

  // ProofSource interface
  bool GetProof(const net::IPEndPoint& server_ip,
                const std::string& hostname,
                const std::string& server_config,
                bool ecdsa_ok,
                const std::vector<std::string>** out_certs,
                std::string* out_signature) override;

 private:
  void* go_quic_dispatcher_;
  std::map<std::string, std::vector<std::string>* > certs_cache_;
  std::vector<std::string> certs_;
  DISALLOW_COPY_AND_ASSIGN(GoProofSource);
};
#endif  // __GO_PROOF_SOURCE__H__
