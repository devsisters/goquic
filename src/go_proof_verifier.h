#ifndef __GO_PROOF_VERIFIER__H__
#define __GO_PROOF_VERIFIER__H__

#include<string>

#include "net/quic/crypto/proof_verifier.h"

namespace net {

class NET_EXPORT_PRIVATE GoProofVerifyDetails : public ProofVerifyDetails {
 public:
  ProofVerifyDetails* Clone() const override {
    // TODO
    return nullptr;
  }

  //CertVerifyResult cert_verify_result;
};

class NET_EXPORT_PRIVATE GoProofVerifier : public ProofVerifier {
 public:
  GoProofVerifier(void* go_proof_verifier);
  ~GoProofVerifier() override;

  // ProofVerifier interface
  QuicAsyncStatus VerifyProof(const std::string& hostname,
                              const std::string& server_config,
                              const std::vector<std::string>& certs,
                              const std::string& cert_sct,
                              const std::string& signature,
                              const ProofVerifyContext* context,
                              std::string* error_details,
                              scoped_ptr<ProofVerifyDetails>* details,
                              ProofVerifierCallback* callback) override;

 private:
  void* go_proof_verifier_;

  DISALLOW_COPY_AND_ASSIGN(GoProofVerifier);
};

} // namespace net

#endif  // __GO_PROOF_VERIFIER__H__
