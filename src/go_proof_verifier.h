#ifndef __GO_PROOF_VERIFIER__H__
#define __GO_PROOF_VERIFIER__H__

#include <string>

#include "net/quic/core/crypto/proof_verifier.h"
#include "go_structs.h"

namespace net {

class NET_EXPORT_PRIVATE GoProofVerifyDetails : public ProofVerifyDetails {
 public:
  ProofVerifyDetails* Clone() const override {
    // TODO
    return nullptr;
  }

  // CertVerifyResult cert_verify_result;
};

class NET_EXPORT_PRIVATE GoProofVerifier : public ProofVerifier {
 public:
  GoProofVerifier(GoPtr go_proof_verifier);
  ~GoProofVerifier() override;

  // ProofVerifier interface
  QuicAsyncStatus VerifyProof(const std::string& hostname,
                              const uint16_t port,
                              const std::string& server_config,
                              QuicVersion quic_version,
                              base::StringPiece chlo_hash,
                              const std::vector<std::string>& certs,
                              const std::string& cert_sct,
                              const std::string& signature,
                              const ProofVerifyContext* context,
                              std::string* error_details,
                              std::unique_ptr<ProofVerifyDetails>* details,
                              std::unique_ptr<ProofVerifierCallback> callback) override;

  QuicAsyncStatus VerifyCertChain(
    const std::string& hostname,
    const std::vector<std::string>& certs,
    const ProofVerifyContext* context,
    std::string* error_details,
    std::unique_ptr<ProofVerifyDetails>* details,
    std::unique_ptr<ProofVerifierCallback> callback) override;
 private:
  GoPtr go_proof_verifier_;

  DISALLOW_COPY_AND_ASSIGN(GoProofVerifier);
};

}  // namespace net

#endif  // __GO_PROOF_VERIFIER__H__
