// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A server specific QuicSession subclass.

#ifndef GO_QUIC_SERVER_SESSION_BASE_H_
#define GO_QUIC_SERVER_SESSION_BASE_H_

#include <stdint.h>

#include <set>
#include <string>
#include <vector>

#include "base/containers/hash_tables.h"
#include "base/memory/scoped_ptr.h"
#include "net/quic/quic_crypto_server_stream.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_spdy_session.h"
#include "go_structs.h"

namespace net {

class QuicBlockedWriterInterface;
class QuicConfig;
class QuicConnection;
class QuicCryptoServerConfig;
class ReliableQuicStream;

// An interface from the session to the entity owning the session.
// This lets the session notify its owner (the Dispatcher) when the connection
// is closed, blocked, or added/removed from the time-wait list.
class GoQuicServerSessionVisitor {
 public:
  virtual ~GoQuicServerSessionVisitor() {}

  virtual void OnConnectionClosed(QuicConnectionId connection_id,
                                  QuicErrorCode error) = 0;
  virtual void OnWriteBlocked(QuicBlockedWriterInterface* blocked_writer) = 0;
  // Called after the given connection is added to the time-wait list.
  virtual void OnConnectionAddedToTimeWaitList(QuicConnectionId connection_id) {
  }
  // Called after the given connection is removed from the time-wait list.
  virtual void OnConnectionRemovedFromTimeWaitList(
      QuicConnectionId connection_id) {}
};

class GoQuicServerSessionBase : public QuicSpdySession {
 public:
  // |crypto_config| must outlive the session.
  GoQuicServerSessionBase(const QuicConfig& config,
                          QuicConnection* connection,
                          GoQuicServerSessionVisitor* visitor,
                          const QuicCryptoServerConfig* crypto_config);

  // Override the base class to notify the owner of the connection close.
  void OnConnectionClosed(QuicErrorCode error,
                          ConnectionCloseSource source) override;
  void OnWriteBlocked() override;

  // Sends a server config update to the client, containing new bandwidth
  // estimate.
  void OnCongestionWindowChange(QuicTime now) override;

  ~GoQuicServerSessionBase() override;

  void Initialize() override;

  const QuicCryptoServerStreamBase* crypto_stream() const {
    return crypto_stream_.get();
  }

  // Override base class to process FEC config received from client.
  void OnConfigNegotiated() override;

  void set_serving_region(std::string serving_region) {
    serving_region_ = serving_region;
  }

  void SetGoSession(GoPtr go_quic_dispatcher, GoPtr go_session) {
    go_quic_dispatcher_ = go_quic_dispatcher;
    go_session_ = go_session;
  }

 protected:
  // QuicSession methods(override them with return type of QuicSpdyStream*):
  QuicCryptoServerStreamBase* GetCryptoStream() override;

  // If an outgoing stream can be created, return true.
  // Return false when connection is closed or forward secure encryption hasn't
  // established yet or number of server initiated streams already reaches the
  // upper limit.
  bool ShouldCreateOutgoingDynamicStream();

  // If we should create an incoming stream, returns true. Otherwise
  // does error handling, including communicating the error to the client and
  // possibly closing the connection, and returns false.
  virtual bool ShouldCreateIncomingDynamicStream(QuicStreamId id);

  virtual QuicCryptoServerStreamBase* CreateQuicCryptoServerStream(
      const QuicCryptoServerConfig* crypto_config) = 0;

  const QuicCryptoServerConfig* crypto_config() { return crypto_config_; }

  GoPtr go_session_;
  GoPtr go_quic_dispatcher_;

 private:
  const QuicCryptoServerConfig* crypto_config_;
  scoped_ptr<QuicCryptoServerStreamBase> crypto_stream_;
  GoQuicServerSessionVisitor* visitor_;

  // Whether bandwidth resumption is enabled for this connection.
  bool bandwidth_resumption_enabled_;

  // The most recent bandwidth estimate sent to the client.
  QuicBandwidth bandwidth_estimate_sent_to_client_;

  // Text describing server location. Sent to the client as part of the bandwith
  // estimate in the source-address token. Optional, can be left empty.
  std::string serving_region_;

  // Time at which we send the last SCUP to the client.
  QuicTime last_scup_time_;

  // Number of packets sent to the peer, at the time we last sent a SCUP.
  int64_t last_scup_packet_number_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicServerSessionBase);
};

}  // namespace net

#endif  // GO_QUIC_SERVER_SESSION_H_
