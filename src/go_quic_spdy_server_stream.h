#ifndef GO_QUIC_SPDY_SERVER_STREAM_H__
#define GO_QUIC_SPDY_SERVER_STREAM_H__

#include <string>

#include "net/quic/quic_spdy_stream.h"

namespace net {

class QuicSpdySession;

namespace tools {

class GoQuicSpdyServerStream : public QuicSpdyStream {
 public:
  GoQuicSpdyServerStream(QuicStreamId id, QuicSpdySession* session);
  ~GoQuicSpdyServerStream() override;

  void SetGoQuicSpdyServerStream(void* go_quic_spdy_server_stream);

  // QuicSpdyStream
  void OnStreamHeadersComplete(bool fin, size_t frame_len) override;

  // ReliableQuicStream implementation called by the sequencer when there is
  // data (or a FIN) to be read.
  void OnDataAvailable() override;

  void OnClose() override;

  // we need a proxy because ReliableQuicStream::WriteOrBufferData is protected.
  // we could access this function from C (go) side.
  void WriteOrBufferData_(base::StringPiece data, bool fin, net::QuicAckListenerInterface* ack_listener);

 private:
  void* go_quic_spdy_server_stream_;

  std::string body_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicSpdyServerStream);
};

}  // namespace tools
}  // namespace net

#endif
