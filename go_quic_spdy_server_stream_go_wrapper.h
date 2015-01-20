#ifndef __GO_QUIC_SPDY_SERVER_STREAM_GO_WRAPPER_H__
#define __GO_QUIC_SPDY_SERVER_STREAM_GO_WRAPPER_H__

#include "net/quic/quic_data_stream.h"

class GoQuicSpdyServerStreamGoWrapper : public net::QuicDataStream {
 public:

  GoQuicSpdyServerStreamGoWrapper(net::QuicStreamId id, net::QuicSession* session, void* go_quic_spdy_server_stream);
  ~GoQuicSpdyServerStreamGoWrapper() override;

  uint32 ProcessData(const char* data, uint32 data_len) override;
  void OnFinRead() override { }

  void ParseRequestHeaders() { }

 private:
  void* go_quic_spdy_server_stream_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicSpdyServerStreamGoWrapper);
};

#endif
