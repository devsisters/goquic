// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A server side dispatcher which dispatches a given client's data to their
// stream.

#ifndef NET_QUIC_QUIC_DISPATCHER_H_
#define NET_QUIC_QUIC_DISPATCHER_H_

#include <list>

#include "go_quic_time_wait_list_manager.h"
#include "go_quic_server_packet_writer.h"
#include "go_quic_server_session.h"

#include "base/basictypes.h"
#include "base/containers/hash_tables.h"
#include "base/memory/scoped_ptr.h"
#include "net/base/ip_endpoint.h"
#include "net/base/linked_hash_map.h"
#include "net/quic/quic_blocked_writer_interface.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_packet_writer.h"
#include "net/quic/quic_connection.h"

namespace net {
namespace test {
class QuicDispatcherPeer;
}  // namespace test

class DeleteSessionsAlarm;
class QuicConfig;
class QuicCryptoServerConfig;
class QuicSession;

class ProcessPacketInterface {
 public:
  virtual ~ProcessPacketInterface() {}
  virtual void ProcessPacket(const IPEndPoint& server_address,
                             const IPEndPoint& client_address,
                             const QuicEncryptedPacket& packet) = 0;
};

class GoQuicDispatcher : public QuicBlockedWriterInterface,
                         public GoQuicServerSessionVisitor,
                         public ProcessPacketInterface {
 public:
  // Creates per-connection packet writers out of the GoQuicDispatcher's shared
  // QuicPacketWriter. The per-connection writers' IsWriteBlocked() state must
  // always be the same as the shared writer's IsWriteBlocked(), or else the
  // GoQuicDispatcher::OnCanWrite logic will not work. (This will hopefully be
  // cleaned up for bug 16950226.)
  class PacketWriterFactory {
   public:
    virtual ~PacketWriterFactory() {}

    virtual QuicPacketWriter* Create(GoQuicServerPacketWriter* writer,
                                     QuicConnection* connection) = 0;
  };

  // Creates ordinary QuicPerConnectionPacketWriter instances.
  class DefaultPacketWriterFactory : public PacketWriterFactory {
   public:
    ~DefaultPacketWriterFactory() override {}

    QuicPacketWriter* Create(GoQuicServerPacketWriter* writer,
                             QuicConnection* connection) override;
  };

  // Ideally we'd have a linked_hash_set: the  boolean is unused.
  typedef linked_hash_map<QuicBlockedWriterInterface*, bool> WriteBlockedList;

  // Due to the way delete_sessions_closure_ is registered, the Dispatcher must
  // live until epoll_server Shutdown. |supported_versions| specifies the list
  // of supported QUIC versions. Takes ownership of |packet_writer_factory|,
  // which is used to create per-connection writers.
  GoQuicDispatcher(const QuicConfig& config,
                   const QuicCryptoServerConfig& crypto_config,
                   const QuicVersionVector& supported_versions,
                   PacketWriterFactory* packet_writer_factory,
                   QuicConnectionHelperInterface* helper,
                   void *go_quic_dispatcher);

  ~GoQuicDispatcher() override;

  // Takes ownership of the packet writer.
  virtual void Initialize(GoQuicServerPacketWriter* writer);

  // Process the incoming packet by creating a new session, passing it to
  // an existing session, or passing it to the TimeWaitListManager.
  void ProcessPacket(const IPEndPoint& server_address,
                     const IPEndPoint& client_address,
                     const QuicEncryptedPacket& packet) override;

  // Returns true if there's anything in the blocked writer list.
  virtual bool HasPendingWrites() const;

  // Sends ConnectionClose frames to all connected clients.
  void Shutdown();

  // QuicBlockedWriterInterface implementation:
  // Called when the socket becomes writable to allow queued writes to happen.
  void OnCanWrite() override;

  // GoQuicServerSessionVisitor interface implementation:
  // Ensure that the closed connection is cleaned up asynchronously.
  void OnConnectionClosed(QuicConnectionId connection_id,
                          QuicErrorCode error) override;

  // Queues the blocked writer for later resumption.
  void OnWriteBlocked(QuicBlockedWriterInterface* blocked_writer) override;

  // Called whenever the QuicTimeWaitListManager adds a new connection to the
  // time-wait list.
  void OnConnectionAddedToTimeWaitList(QuicConnectionId connection_id) override;

  // Called whenever the QuicTimeWaitListManager removes an old connection from
  // the time-wait list.
  void OnConnectionRemovedFromTimeWaitList(
      QuicConnectionId connection_id) override;

  typedef base::hash_map<QuicConnectionId, QuicSession*> SessionMap;

  // Deletes all sessions on the closed session list and clears the list.
  void DeleteSessions();

  const SessionMap& session_map() const { return session_map_; }

 protected:
  virtual QuicSession* CreateQuicSession(QuicConnectionId connection_id,
                                         const IPEndPoint& server_address,
                                         const IPEndPoint& client_address);

  virtual QuicConnection* CreateQuicConnection(
      QuicConnectionId connection_id,
      const IPEndPoint& server_address,
      const IPEndPoint& client_address);

  // Called by |framer_visitor_| when the public header has been parsed.
  virtual bool OnUnauthenticatedPublicHeader(
      const QuicPacketPublicHeader& header);

  // Create and return the time wait list manager for this dispatcher, which
  // will be owned by the dispatcher as time_wait_list_manager_
  virtual GoQuicTimeWaitListManager* CreateQuicTimeWaitListManager();

  // Replaces the packet writer with |writer|. Takes ownership of |writer|.
  void set_writer(GoQuicServerPacketWriter* writer) {
    writer_.reset(writer);
  }

  GoQuicTimeWaitListManager* time_wait_list_manager() {
    return time_wait_list_manager_.get();
  }

  const QuicVersionVector& supported_versions() const {
    return supported_versions_;
  }

  const IPEndPoint& current_server_address() {
    return current_server_address_;
  }
  const IPEndPoint& current_client_address() {
    return current_client_address_;
  }
  const QuicEncryptedPacket& current_packet() {
    return *current_packet_;
  }

  const QuicConfig& config() const { return config_; }

  const QuicCryptoServerConfig& crypto_config() const { return crypto_config_; }

  QuicFramer* framer() { return &framer_; }

  QuicConnectionHelperInterface* helper() { return helper_; }

  GoQuicServerPacketWriter* writer() { return writer_.get(); }

  const QuicConnection::PacketWriterFactory& connection_writer_factory() {
    return connection_writer_factory_;
  }

 private:
  class QuicFramerVisitor;
  friend class net::test::QuicDispatcherPeer;

  // An adapter that creates packet writers using the dispatcher's
  // PacketWriterFactory and shared writer. Essentially, it just curries the
  // writer argument away from QuicDispatcher::PacketWriterFactory.
  class PacketWriterFactoryAdapter :
    public QuicConnection::PacketWriterFactory {
   public:
    PacketWriterFactoryAdapter(GoQuicDispatcher* dispatcher);
    ~PacketWriterFactoryAdapter() override;

    QuicPacketWriter* Create(QuicConnection* connection) const override;

   private:
    GoQuicDispatcher* dispatcher_;
  };

  // Called by |framer_visitor_| when the private header has been parsed
  // of a data packet that is destined for the time wait manager.
  void OnUnauthenticatedHeader(const QuicPacketHeader& header);

  // Removes the session from the session map and write blocked list, and
  // adds the ConnectionId to the time-wait list.
  void CleanUpSession(SessionMap::iterator it);

  bool HandlePacketForTimeWait(const QuicPacketPublicHeader& header);

  const QuicConfig& config_;

  const QuicCryptoServerConfig& crypto_config_;

  // The list of connections waiting to write.
  WriteBlockedList write_blocked_list_;

  SessionMap session_map_;

  // Entity that manages connection_ids in time wait state.
  scoped_ptr<GoQuicTimeWaitListManager> time_wait_list_manager_;

  // The helper used for all connections. Owned by the server.
  QuicConnectionHelperInterface* helper_;

  // An alarm which deletes closed sessions.
  scoped_ptr<QuicAlarm> delete_sessions_alarm_;

  // The list of closed but not-yet-deleted sessions.
  std::list<QuicSession*> closed_session_list_;

  // The writer to write to the socket with.
  scoped_ptr<GoQuicServerPacketWriter> writer_;

  // Used to create per-connection packet writers, not |writer_| itself.
  scoped_ptr<PacketWriterFactory> packet_writer_factory_;

  // Passed in to QuicConnection for it to create the per-connection writers
  PacketWriterFactoryAdapter connection_writer_factory_;

  // This vector contains QUIC versions which we currently support.
  // This should be ordered such that the highest supported version is the first
  // element, with subsequent elements in descending order (versions can be
  // skipped as necessary).
  const QuicVersionVector supported_versions_;

  // Information about the packet currently being handled.
  IPEndPoint current_client_address_;
  IPEndPoint current_server_address_;
  const QuicEncryptedPacket* current_packet_;

  QuicFramer framer_;
  scoped_ptr<QuicFramerVisitor> framer_visitor_;

  void *go_quic_dispatcher_;

  DISALLOW_COPY_AND_ASSIGN(GoQuicDispatcher);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_DISPATCHER_H_
