#ifndef __GO_QUIC_SPDY_SERVER_STREAM_GO_WRAPPER_H__
#define __GO_QUIC_SPDY_SERVER_STREAM_GO_WRAPPER_H__

#include "net/quic/quic_data_stream.h"
#include "net/quic/quic_ack_notifier.h"
#include "base/strings/string_piece.h"

class GoQuicSpdyServerStreamGoWrapper : public net::QuicDataStream {
 public:

  GoQuicSpdyServerStreamGoWrapper(net::QuicStreamId id, net::QuicSession* session);
  ~GoQuicSpdyServerStreamGoWrapper() override;

  void SetGoQuicSpdyServerStream(void* go_quic_spdy_server_stream);

  uint32 ProcessData(const char* data, uint32 data_len) override;
  void OnFinRead() override;

  // we need a proxy because ReliableQuicStream::WriteOrBufferData & CloseReadSide() is protected.
  // we could access this function from C (go) side.
  void WriteOrBufferData_(base::StringPiece buffer, bool fin, net::QuicAckNotifier::DelegateInterface* delegate);
  void CloseReadSide_();

 private:
  void* go_quic_spdy_server_stream_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicSpdyServerStreamGoWrapper);
};

#endif
