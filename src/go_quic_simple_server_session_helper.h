#ifndef GO_QUIC_SIMPLE_SERVER_SESSION_HELPER_H_
#define GO_QUIC_SIMPLE_SERVER_SESSION_HELPER_H_

#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/quic_server_session_base.h"

namespace net {

// Simple helper for server sessions which generates a new random
// connection ID for stateless rejects.
class GoQuicSimpleServerSessionHelper : public QuicCryptoServerStream::Helper {
 public:
  explicit GoQuicSimpleServerSessionHelper(QuicRandom* random);

  ~GoQuicSimpleServerSessionHelper() override;

  QuicConnectionId GenerateConnectionIdForReject(
      QuicConnectionId /*connection_id*/) const override;

  bool CanAcceptClientHello(const CryptoHandshakeMessage& message,
                            const IPEndPoint& self_address,
                            std::string* error_details) const override;

 private:
  QuicRandom* random_;  // Unowned.
};

}  // namespace net

#endif  // GO_QUIC_SIMPLE_SERVER_SESSION_HELPER_H_
