#ifndef GO_QUIC_SIMPLE_SERVER_STREAM_H__
#define GO_QUIC_SIMPLE_SERVER_STREAM_H__

#include <string>

#include "net/quic/quic_spdy_stream.h"

namespace net {

class QuicSpdySession;

namespace tools {

class GoQuicSimpleServerStream : public QuicSpdyStream {
 public:
  GoQuicSimpleServerStream(QuicStreamId id, QuicSpdySession* session);
  ~GoQuicSimpleServerStream() override;

  void SetGoQuicSimpleServerStream(void* go_quic_simple_server_stream);

  // QuicSpdyStream
  void OnInitialHeadersComplete(bool fin, size_t frame_len) override;
  void OnTrailingHeadersComplete(bool fin, size_t frame_len) override;

  // ReliableQuicStream implementation called by the sequencer when there is
  // data (or a FIN) to be read.
  void OnDataAvailable() override;

  void OnClose() override;

  // we need a proxy because ReliableQuicStream::WriteOrBufferData is protected.
  // we could access this function from C (go) side.
  void WriteOrBufferData_(base::StringPiece data,
                          bool fin,
                          net::QuicAckListenerInterface* ack_listener);

 private:
  void* go_quic_simple_server_stream_;

  std::string body_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicSimpleServerStream);
};

}  // namespace tools
}  // namespace net

#endif
