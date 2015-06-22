#ifndef NET_QUIC_QUIC_CLIENT_SESSION_H_
#define NET_QUIC_QUIC_CLIENT_SESSION_H_

#include "go_quic_reliable_client_stream.h"

#include "net/quic/quic_crypto_client_stream.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/quic_client_session_base.h"

namespace net {

class QuicConnectionHelperInterface;
class QuicCryptoClientConfig;

class NET_EXPORT_PRIVATE GoQuicClientSession : public QuicClientSessionBase {
 public:
   GoQuicClientSession(const QuicConfig& config, QuicConnection* connection, QuicConnectionHelperInterface* helper);
   ~GoQuicClientSession() override;

   void InitializeSession(const QuicServerId& server_id,
                          QuicCryptoClientConfig* config);

   // QuicSession methods:
   GoQuicReliableClientStream* CreateOutgoingDynamicStream() override;

   QuicCryptoClientStream* GetCryptoStream() override;

   // QuicClientSessionBase methods:
   void OnProofValid(const QuicCryptoClientConfig::CachedState& cached) override;
   void OnProofVerifyDetailsAvailable(
       const ProofVerifyDetails& verify_details) override;

   // Performs a crypto handshake with the server
   void CryptoConnect();

   QuicConnectionHelperInterface* helper() { return helper_; }

 protected:
  QuicDataStream* CreateIncomingDynamicStream(QuicStreamId id) override;  
 private:
  scoped_ptr<QuicCryptoClientStream> crypto_stream_;
  QuicConnectionHelperInterface* helper_;

  QuicCryptoClientConfig* crypto_config_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicClientSession);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_CLIENT_SESSION_H_
