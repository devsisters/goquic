#include "go_ephemeral_key_source.h"

namespace net {

GoEphemeralKeySource::GoEphemeralKeySource()
    : forward_secure_key_exchange_(nullptr),
      key_created_time_(net::QuicTime::Zero()) {}

std::string GoEphemeralKeySource::CalculateForwardSecureKey(
    const net::KeyExchange* key_exchange,
    net::QuicRandom* rand,
    net::QuicTime now,
    base::StringPiece peer_public_value,
    std::string* public_value) {
  // Cache forward_secure_key_exchange for 10 seconds
  if (forward_secure_key_exchange_.get() == nullptr ||
      (now - key_created_time_).ToSeconds() > 10) {
    forward_secure_key_exchange_.reset(key_exchange->NewKeyPair(rand));
    key_created_time_ = now;
  }

  *public_value = forward_secure_key_exchange_->public_value().as_string();
  std::string forward_secure_premaster_secret;
  forward_secure_key_exchange_->CalculateSharedKey(
      peer_public_value, &forward_secure_premaster_secret);
  return forward_secure_premaster_secret;
}

}   // namespace net
