#ifndef __PROOF_SOURCE_GOQUIC__H__
#define __PROOF_SOURCE_GOQUIC__H__

#include <map>

#include "net/quic/core/crypto/proof_source.h"
#include "net/base/host_port_pair.h"
#include "go_structs.h"

namespace net {

class IPAddress;

// This should be thread-safe, because multiple dispatcher may concurrently call
// GetProof()
class ProofSourceGoquic : public ProofSource {
 public:
  ProofSourceGoquic(GoPtr go_proof_source);
  ~ProofSourceGoquic() override;

  // Initialize functions.
  // BuildCertChain should be called after all certs be added.
  void AddCert(char* cert_c, size_t cert_sz);
  void BuildCertChain();

  // ProofSource interface
  bool GetProof(const IPAddress& server_ip,
                const std::string& hostname,
                const std::string& server_config,
                QuicVersion quic_version,
                base::StringPiece chlo_hash,
                scoped_refptr<ProofSource::Chain>* out_chain,
                std::string* out_signature,
                std::string* out_leaf_cert_sct) override;

  void GetProof(const IPAddress& server_ip,
                const std::string& hostname,
                const std::string& server_config,
                QuicVersion quic_version,
                base::StringPiece chlo_hash,
                std::unique_ptr<Callback> callback) override;

 private:
  GoPtr go_proof_source_;
  //std::map<std::string, std::vector<std::string>*> certs_cache_;
  std::vector<std::string> certs_;
  scoped_refptr<ProofSource::Chain> chain_;
  DISALLOW_COPY_AND_ASSIGN(ProofSourceGoquic);
};

}    // namespace net

#endif  // __PROOF_SOURCE_GOQUIC__H__
