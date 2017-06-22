#ifndef __GO_EPHEMERAL_KEY_SOURCE__H__
#define __GO_EPHEMERAL_KEY_SOURCE__H__

#include "net/quic/core/crypto/key_exchange.h"
#include "net/quic/core/crypto/ephemeral_key_source.h"
#include "net/quic/core/quic_time.h"

namespace net {

class GoEphemeralKeySource : public EphemeralKeySource {
 public:
  GoEphemeralKeySource();

  virtual std::string CalculateForwardSecureKey(
      const KeyExchange* key_exchange,
      QuicRandom* rand,
      QuicTime now,
      base::StringPiece peer_public_value,
      std::string* public_value) override;

 private:
  std::unique_ptr<net::KeyExchange> forward_secure_key_exchange_;
  QuicTime key_created_time_;
};

}   // namespace net

#endif  // __GO_EPHEMERAL_KEY_SOURCE__H__
