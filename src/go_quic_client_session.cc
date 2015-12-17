#include "go_quic_client_session.h"

#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/quic_server_id.h"
#include "go_quic_spdy_client_stream.h"

namespace net {
namespace tools {

GoQuicClientSession::GoQuicClientSession(const QuicConfig& config,
                                         QuicConnection* connection,
                                         const QuicServerId& server_id,
                                         QuicCryptoClientConfig* crypto_config)
    : QuicClientSessionBase(connection, config),
      server_id_(server_id),
      crypto_config_(crypto_config),
      respect_goaway_(true) {}

GoQuicClientSession::~GoQuicClientSession() {
}

void GoQuicClientSession::Initialize() {
  crypto_stream_.reset(CreateQuicCryptoStream());
  QuicClientSessionBase::Initialize();
}

void GoQuicClientSession::OnProofValid(
    const QuicCryptoClientConfig::CachedState& /*cached*/) {}

void GoQuicClientSession::OnProofVerifyDetailsAvailable(
    const ProofVerifyDetails& /*verify_details*/) {}

GoQuicSpdyClientStream* GoQuicClientSession::CreateOutgoingDynamicStream(
    SpdyPriority priority) {
  if (!crypto_stream_->encryption_established()) {
    DVLOG(1) << "Encryption not active so no outgoing stream created.";
    return nullptr;
  }
  if (GetNumOpenOutgoingStreams() >= get_max_open_streams()) {
    DVLOG(1) << "Failed to create a new outgoing stream. "
             << "Already " << GetNumOpenOutgoingStreams() << " open.";
    return nullptr;
  }
  if (goaway_received() && respect_goaway_) {
    DVLOG(1) << "Failed to create a new outgoing stream. "
             << "Already received goaway.";
    return nullptr;
  }
  GoQuicSpdyClientStream* stream = CreateClientStream();
  stream->SetPriority(priority);
  ActivateStream(stream);
  return stream;
}

GoQuicSpdyClientStream* GoQuicClientSession::CreateClientStream() {
  return new GoQuicSpdyClientStream(GetNextOutgoingStreamId(), this);
}

QuicCryptoClientStreamBase* GoQuicClientSession::GetCryptoStream() {
  return crypto_stream_.get();
}

void GoQuicClientSession::CryptoConnect() {
  DCHECK(flow_controller());
  crypto_stream_->CryptoConnect();
}

int GoQuicClientSession::GetNumSentClientHellos() const {
  return crypto_stream_->num_sent_client_hellos();
}

QuicSpdyStream* GoQuicClientSession::CreateIncomingDynamicStream(
    QuicStreamId id) {
  // TODO(hodduc) Support server push
  DLOG(ERROR) << "Server push not supported";
  return nullptr;
}

QuicCryptoClientStreamBase* GoQuicClientSession::CreateQuicCryptoStream() {
  return new QuicCryptoClientStream(server_id_, this, nullptr, crypto_config_);
  // XXX(hodduc) third parameter is for implementation-specific context, which is nullable.
}

}  // namespace tools

}   // namespace net
