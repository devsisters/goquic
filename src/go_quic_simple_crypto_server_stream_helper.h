#ifndef GO_QUIC_SIMPLE_CRYPTO_SERVER_STREAM_HELPER_H_
#define GO_QUIC_SIMPLE_CRYPTO_SERVER_STREAM_HELPER_H_

#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/quic_crypto_server_stream.h"

namespace net {

// Simple helper for server sessions which generates a new random
// connection ID for stateless rejects.
class GoQuicSimpleCryptoServerStreamHelper
    : public QuicCryptoServerStream::Helper {
 public:
  explicit GoQuicSimpleCryptoServerStreamHelper(QuicRandom* random);

  ~GoQuicSimpleCryptoServerStreamHelper() override;

  QuicConnectionId GenerateConnectionIdForReject(
      QuicConnectionId /*connection_id*/) const override;

  bool CanAcceptClientHello(const CryptoHandshakeMessage& message,
                            const IPEndPoint& self_address,
                            std::string* error_details) const override;

 private:
  QuicRandom* random_;  // Unowned.
};

}  // namespace net

#endif  // GO_QUIC_SIMPLE_CRYPTO_SERVER_STREAM_HELPER_H_
