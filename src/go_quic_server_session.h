// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A server specific QuicSession subclass.

#ifndef NET_QUIC_QUIC_SERVER_SESSION_H_
#define NET_QUIC_QUIC_SERVER_SESSION_H_

#include <set>
#include <string>
#include <vector>

#include "base/basictypes.h"
#include "base/containers/hash_tables.h"
#include "base/memory/scoped_ptr.h"
#include "net/quic/quic_crypto_server_stream.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_session.h"
#include "net/quic/quic_data_stream.h"

namespace net {

namespace test {
class QuicServerSessionPeer;
}  // namespace test

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

class GoQuicServerSession : public QuicSession {
 public:
  GoQuicServerSession(const QuicConfig& config,
                    QuicConnection* connection,
                    GoQuicServerSessionVisitor* visitor);

  // Override the base class to notify the owner of the connection close.
  void OnConnectionClosed(QuicErrorCode error, bool from_peer) override;
  void OnWriteBlocked() override;

  // Sends a server config update to the client, containing new bandwidth
  // estimate.
  void OnCongestionWindowChange(QuicTime now) override;

  ~GoQuicServerSession() override;

  virtual void InitializeSession(const QuicCryptoServerConfig& crypto_config);

  const QuicCryptoServerStream* crypto_stream() const {
    return crypto_stream_.get();
  }

  // Override base class to process FEC config received from client.
  void OnConfigNegotiated() override;

  void set_serving_region(std::string serving_region) {
    serving_region_ = serving_region;
  }

  void SetGoSession(void* go_quic_dispatcher, void* go_session) {
    go_quic_dispatcher_ = go_quic_dispatcher;
    go_session_ = go_session;
  }

  void* GetGoSession() {
    return go_session_;
  }

 protected:
  // QuicSession methods:
  QuicDataStream* CreateIncomingDynamicStream(QuicStreamId id) override;
  QuicDataStream* CreateOutgoingDynamicStream() override;
  QuicCryptoServerStream* GetCryptoStream() override;

  // If we should create an incoming stream, returns true. Otherwise
  // does error handling, including communicating the error to the client and
  // possibly closing the connection, and returns false.
  virtual bool ShouldCreateIncomingDynamicStream(QuicStreamId id);

  virtual QuicCryptoServerStream* CreateQuicCryptoServerStream(
      const QuicCryptoServerConfig& crypto_config);

 private:
  friend class test::QuicServerSessionPeer;

  scoped_ptr<QuicCryptoServerStream> crypto_stream_;
  GoQuicServerSessionVisitor* visitor_;

  // The most recent bandwidth estimate sent to the client.
  QuicBandwidth bandwidth_estimate_sent_to_client_;

  // Text describing server location. Sent to the client as part of the bandwith
  // estimate in the source-address token. Optional, can be left empty.
  std::string serving_region_;

  // Time at which we send the last SCUP to the client.
  QuicTime last_scup_time_;

  // Number of packets sent to the peer, at the time we last sent a SCUP.
  int64 last_scup_sequence_number_;

  void *go_session_;
  void *go_quic_dispatcher_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicServerSession);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_SERVER_SESSION_H_
