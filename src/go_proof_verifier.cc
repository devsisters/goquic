#include "go_proof_verifier.h"
#include "go_functions.h"

#include "base/logging.h"

namespace net {

GoProofVerifier::GoProofVerifier(GoPtr go_proof_verifier)
    : go_proof_verifier_(go_proof_verifier) {}

GoProofVerifier::~GoProofVerifier() {
  ReleaseProofVerifier_C(go_proof_verifier_);
}

QuicAsyncStatus GoProofVerifier::VerifyProof(
    const std::string& hostname,
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
    std::unique_ptr<ProofVerifierCallback> callback) {
  // XXX(hodduc): Should we implement verifying on go-side asynchronously?
  // XXX(hodduc): QUIC_VERSION_31 support

  std::unique_ptr<GoProofVerifyDetails> verify_details_;
  verify_details_.reset(new GoProofVerifyDetails);

  if (certs.empty()) {
    *error_details = "Failed to create certificate chain. Certs are empty.";
    DLOG(WARNING) << *error_details;
    //    verify_details_->cert_verify_result.cert_status = CERT_STATUS_INVALID;
    *details = std::move(verify_details_);
    return QUIC_FAILURE;
  }

  auto chlo_hash_str = chlo_hash.as_string();

  // Convery certs to X509Certificate.
  GoPtr job = NewProofVerifyJob_C(
      go_proof_verifier_, (int)(quic_version),
      (char*)(hostname.c_str()), (size_t)(hostname.length()),
      (char*)(server_config.c_str()), (size_t)(server_config.length()),
      (char*)(chlo_hash_str.c_str()), (size_t)(chlo_hash_str.length()),
      (char*)(cert_sct.c_str()), (size_t)(cert_sct.length()),
      (char*)(signature.c_str()), (size_t)(signature.length()));

  for (auto it = certs.begin(); it != certs.end(); it++) {
    ProofVerifyJobAddCert_C(job, (char*)it->c_str(), (size_t)it->length());
  }

  // TODO(hodduc) detailed error msg
  int ret = ProofVerifyJobVerifyProof_C(job);

  if (ret == 1) {
    *details = std::move(verify_details_);
    return QUIC_SUCCESS;
  } else {
    *error_details = "Failed to verify proof";
    DLOG(WARNING) << *error_details;
    *details = std::move(verify_details_);
    return QUIC_FAILURE;
  }
}

QuicAsyncStatus GoProofVerifier::VerifyCertChain(
     const std::string& hostname,
     const std::vector<std::string>& certs,
     const ProofVerifyContext* context,
     std::string* error_details,
     std::unique_ptr<ProofVerifyDetails>* details,
     std::unique_ptr<ProofVerifierCallback> callback) {
  // TODO(hodduc)
}

}  // namespace net
