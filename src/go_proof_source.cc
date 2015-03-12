#include "go_proof_source.h"

#include "base/logging.h"

#include "go_functions.h"

GoProofSource::GoProofSource(void* go_quic_dispatcher) : go_quic_dispatcher_(go_quic_dispatcher), certs_(2) {
    certs_[0] = "0";
    certs_[1] = "1";
}
GoProofSource::~GoProofSource() {}

// ProofSource interface
bool GoProofSource::GetProof(const net::IPEndPoint& server_ip,
        const std::string& hostname,
        const std::string& server_config,
        bool ecdsa_ok,
        const std::vector<std::string>** out_certs,
        std::string* out_signature) {
    char **c_certs;
    int c_certs_sz;
    char *c_out_signature;
    size_t *c_certs_item_sz;
    size_t c_out_signature_sz;

    GetProof_C(go_quic_dispatcher_, (void*)(&server_ip), (char*)hostname.c_str(), (size_t)hostname.length(), (char*)server_config.c_str(), (size_t)server_config.length(), ecdsa_ok, &c_certs, &c_certs_sz, &c_certs_item_sz, &c_out_signature, &c_out_signature_sz);

    std::vector<std::string> *certs = new std::vector<std::string>;
    for (int i = 0; i < c_certs_sz; i++) {
        certs->push_back(std::string(c_certs[i], c_certs_item_sz[i]));
        free(c_certs[i]);  // Created from go side
    }
    // XXX(serialx): certs_cache_ only keeps growing. And we don't actually use it for cache. :(
    auto it = certs_cache_.find(hostname);
    if (it != certs_cache_.end()) {
        certs_cache_.erase(it);  // Erase former allocated vector
        delete it->second;
    }
    certs_cache_[hostname] = certs;

    std::string signature(c_out_signature, c_out_signature_sz);
    free(c_out_signature);  // Created from go side

    *out_certs = certs;
    *out_signature = signature;
    return true;
}
