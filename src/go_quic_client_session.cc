#include "go_quic_client_session.h"
#include "go_quic_reliable_client_stream.h"

#include "net/quic/quic_connection.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/quic_crypto_client_stream.h"
#include "net/quic/quic_server_id.h"

namespace net {

GoQuicClientSession::GoQuicClientSession(const QuicConfig& config,
                                         QuicConnection* connection,
                                         QuicConnectionHelperInterface* helper)
    : QuicClientSessionBase(connection, config),
      helper_(helper) {
}

GoQuicClientSession::~GoQuicClientSession() {
  delete crypto_config_;
}

void GoQuicClientSession::InitializeSession(
    const QuicServerId& server_id,
    QuicCryptoClientConfig* crypto_config
    ) {
  crypto_stream_.reset(
      new QuicCryptoClientStream(server_id, this, nullptr, crypto_config));
  crypto_config_ = crypto_config;
  QuicClientSessionBase::InitializeSession();
}

void GoQuicClientSession::OnProofValid(
    const QuicCryptoClientConfig::CachedState& /*cached*/) {}

void GoQuicClientSession::OnProofVerifyDetailsAvailable(
    const ProofVerifyDetails& /*verify_details*/) {}

GoQuicReliableClientStream* GoQuicClientSession::CreateOutgoingDataStream() {
  if (!crypto_stream_->encryption_established()) {
    DVLOG(1) << "Encryption not active so no outgoing stream created.";
    return nullptr;
  }
  if (GetNumOpenStreams() >= get_max_open_streams()) {
    DVLOG(1) << "Failed to create a new outgoing stream. "
             << "Already " << GetNumOpenStreams() << " open.";
    return nullptr;
  }
  if (goaway_received()) {
    DVLOG(1) << "Failed to create a new outgoing stream. "
             << "Already received goaway.";
    return nullptr;
  }
  GoQuicReliableClientStream* stream
      = new GoQuicReliableClientStream(GetNextStreamId(), this);
  ActivateStream(stream);
  return stream;
}

QuicCryptoClientStream* GoQuicClientSession::GetCryptoStream() {
  return crypto_stream_.get();
}

void GoQuicClientSession::CryptoConnect() {
  DCHECK(flow_controller());
  crypto_stream_->CryptoConnect();
}

QuicDataStream* GoQuicClientSession::CreateIncomingDataStream(QuicStreamId id) {
  // TODO(hodduc) Support server push
  return nullptr;
}

}   // namespace net
