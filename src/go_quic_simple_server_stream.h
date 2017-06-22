#ifndef GO_QUIC_SIMPLE_SERVER_STREAM_H__
#define GO_QUIC_SIMPLE_SERVER_STREAM_H__

#include <string>

#include "net/quic/core/quic_spdy_stream.h"
#include "go_structs.h"

namespace net {

class QuicSpdySession;

class GoQuicSimpleServerStream : public QuicSpdyStream {
 public:
  GoQuicSimpleServerStream(QuicStreamId id, QuicSpdySession* session);
  ~GoQuicSimpleServerStream() override;

  void SetGoQuicSimpleServerStream(GoPtr go_quic_simple_server_stream);

  // QuicSpdyStream
  void OnInitialHeadersComplete(bool fin, size_t frame_len) override;
  void OnTrailingHeadersComplete(bool fin, size_t frame_len) override;
  void OnInitialHeadersComplete(bool fin,
                                size_t frame_len,
                                const QuicHeaderList& header_list) override;
  void OnTrailingHeadersComplete(bool fin,
                                 size_t frame_len,
                                 const QuicHeaderList& header_list) override;

  // ReliableQuicStream implementation called by the sequencer when there is
  // data (or a FIN) to be read.
  void OnDataAvailable() override;

  void OnClose() override;

  // The response body of error responses.
  static const char* const kErrorResponseBody;
  static const char* const kNotFoundResponseBody;

  size_t WriteHeaders(SpdyHeaderBlock header_block,
                      bool fin,
                      QuicAckListenerInterface* ack_notifier_delegate) override;

 protected:
  // Sends a basic 500 response using SendHeaders for the headers and WriteData
  // for the body.
  virtual void SendErrorResponse();

 private:
  GoPtr go_quic_simple_server_stream_;

  SpdyHeaderBlock request_headers_;
  int64_t content_length_;
  std::string body_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicSimpleServerStream);
};

}  // namespace net

#endif
