// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "go_quic_time_wait_list_manager.h"

#include "go_quic_server_session.h"

#include <errno.h>

#include "base/containers/hash_tables.h"
#include "base/memory/scoped_ptr.h"
#include "base/stl_util.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/crypto/quic_decrypter.h"
#include "net/quic/crypto/quic_encrypter.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_framer.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_utils.h"
#include "net/quic/quic_connection.h"

using base::StringPiece;
using std::make_pair;

namespace net {

namespace {

// Time period for which a given connection_id should live in the time-wait
// state.
int64 FLAGS_quic_time_wait_list_seconds = 5;

}  // namespace

// A very simple alarm that just informs the GoQuicTimeWaitListManager to clean
// up old connection_ids. This alarm should be unregistered and deleted before
// the GoQuicTimeWaitListManager is deleted.
class ConnectionIdCleanUpAlarm : public QuicAlarm::Delegate {
 public:
  explicit ConnectionIdCleanUpAlarm(
      GoQuicTimeWaitListManager* time_wait_list_manager)
      : time_wait_list_manager_(time_wait_list_manager) {
  }

  QuicTime OnAlarm() override {
    time_wait_list_manager_->CleanUpOldConnectionIds();
    // Let the time wait manager register the alarm at appropriate time.
    return QuicTime::Zero();
  }

 private:
  // Not owned.
  GoQuicTimeWaitListManager* time_wait_list_manager_;
};

// This class stores pending public reset packets to be sent to clients.
// server_address - server address on which a packet what was received for
//                  a connection_id in time wait state.
// client_address - address of the client that sent that packet. Needed to send
//                  the public reset packet back to the client.
// packet - the pending public reset packet that is to be sent to the client.
//          created instance takes the ownership of this packet.
class GoQuicTimeWaitListManager::QueuedPacket {
 public:
  QueuedPacket(const IPEndPoint& server_address,
               const IPEndPoint& client_address,
               QuicEncryptedPacket* packet)
      : server_address_(server_address),
        client_address_(client_address),
        packet_(packet) {
  }

  const IPEndPoint& server_address() const { return server_address_; }
  const IPEndPoint& client_address() const { return client_address_; }
  QuicEncryptedPacket* packet() { return packet_.get(); }

 private:
  const IPEndPoint server_address_;
  const IPEndPoint client_address_;
  scoped_ptr<QuicEncryptedPacket> packet_;

  DISALLOW_COPY_AND_ASSIGN(QueuedPacket);
};

GoQuicTimeWaitListManager::GoQuicTimeWaitListManager(
    QuicPacketWriter* writer,
    GoQuicServerSessionVisitor* visitor,
    QuicConnectionHelperInterface* helper,
    const QuicVersionVector& supported_versions)
    : helper_(helper),
      kTimeWaitPeriod_(
          QuicTime::Delta::FromSeconds(FLAGS_quic_time_wait_list_seconds)),
      connection_id_clean_up_alarm_(
          helper_->CreateAlarm(new ConnectionIdCleanUpAlarm(this))),
      writer_(writer),
      visitor_(visitor) {
  SetConnectionIdCleanUpAlarm();
}

GoQuicTimeWaitListManager::~GoQuicTimeWaitListManager() {
  connection_id_clean_up_alarm_->Cancel();
  STLDeleteElements(&pending_packets_queue_);
  for (ConnectionIdMap::iterator it = connection_id_map_.begin();
       it != connection_id_map_.end();
       ++it) {
    delete it->second.close_packet;
  }
}

void GoQuicTimeWaitListManager::AddConnectionIdToTimeWait(
    QuicConnectionId connection_id,
    QuicVersion version,
    QuicEncryptedPacket* close_packet) {
  int num_packets = 0;
  ConnectionIdMap::iterator it = connection_id_map_.find(connection_id);
  const bool new_connection_id = it == connection_id_map_.end();
  if (!new_connection_id) {  // Replace record if it is reinserted.
    num_packets = it->second.num_packets;
    delete it->second.close_packet;
    connection_id_map_.erase(it);
  }
  ConnectionIdData data(num_packets,
                        version,
                        helper_->GetClock()->ApproximateNow(),
                        close_packet);
  connection_id_map_.insert(make_pair(connection_id, data));
  if (new_connection_id) {
    visitor_->OnConnectionAddedToTimeWaitList(connection_id);
  }
}

bool GoQuicTimeWaitListManager::IsConnectionIdInTimeWait(
    QuicConnectionId connection_id) const {
  return ContainsKey(connection_id_map_, connection_id);
}

QuicVersion GoQuicTimeWaitListManager::GetQuicVersionFromConnectionId(
    QuicConnectionId connection_id) {
  ConnectionIdMap::iterator it = connection_id_map_.find(connection_id);
  DCHECK(it != connection_id_map_.end());
  return (it->second).version;
}

void GoQuicTimeWaitListManager::OnCanWrite() {
  while (!pending_packets_queue_.empty()) {
    QueuedPacket* queued_packet = pending_packets_queue_.front();
    if (!WriteToWire(queued_packet)) {
      return;
    }
    pending_packets_queue_.pop_front();
    delete queued_packet;
  }
}

void GoQuicTimeWaitListManager::ProcessPacket(
    const IPEndPoint& server_address,
    const IPEndPoint& client_address,
    QuicConnectionId connection_id,
    QuicPacketSequenceNumber sequence_number,
    const QuicEncryptedPacket& /*packet*/) {
  DCHECK(IsConnectionIdInTimeWait(connection_id));
  DVLOG(1) << "Processing " << connection_id << " in time wait state.";
  // TODO(satyamshekhar): Think about handling packets from different client
  // addresses.
  ConnectionIdMap::iterator it = connection_id_map_.find(connection_id);
  DCHECK(it != connection_id_map_.end());
  // Increment the received packet count.
  ++((it->second).num_packets);
  if (!ShouldSendResponse((it->second).num_packets)) {
    return;
  }
  if (it->second.close_packet) {
    QueuedPacket* queued_packet =
        new QueuedPacket(server_address,
                         client_address,
                         it->second.close_packet->Clone());
    // Takes ownership of the packet.
    SendOrQueuePacket(queued_packet);
  } else {
    SendPublicReset(server_address,
                    client_address,
                    connection_id,
                    sequence_number);
  }
}

// Returns true if the number of packets received for this connection_id is a
// power of 2 to throttle the number of public reset packets we send to a
// client.
bool GoQuicTimeWaitListManager::ShouldSendResponse(int received_packet_count) {
  return (received_packet_count & (received_packet_count - 1)) == 0;
}

void GoQuicTimeWaitListManager::SendPublicReset(
    const IPEndPoint& server_address,
    const IPEndPoint& client_address,
    QuicConnectionId connection_id,
    QuicPacketSequenceNumber rejected_sequence_number) {
  QuicPublicResetPacket packet;
  packet.public_header.connection_id = connection_id;
  packet.public_header.reset_flag = true;
  packet.public_header.version_flag = false;
  packet.rejected_sequence_number = rejected_sequence_number;
  // TODO(satyamshekhar): generate a valid nonce for this connection_id.
  packet.nonce_proof = 1010101;
  packet.client_address = client_address;
  QueuedPacket* queued_packet = new QueuedPacket(
      server_address,
      client_address,
      BuildPublicReset(packet));
  // Takes ownership of the packet.
  SendOrQueuePacket(queued_packet);
}

QuicEncryptedPacket* GoQuicTimeWaitListManager::BuildPublicReset(
    const QuicPublicResetPacket& packet) {
  return QuicFramer::BuildPublicResetPacket(packet);
}

// Either sends the packet and deletes it or makes pending queue the
// owner of the packet.
void GoQuicTimeWaitListManager::SendOrQueuePacket(QueuedPacket* packet) {
  if (WriteToWire(packet)) {
    delete packet;
  } else {
    // pending_packets_queue takes the ownership of the queued packet.
    pending_packets_queue_.push_back(packet);
  }
}

bool GoQuicTimeWaitListManager::WriteToWire(QueuedPacket* queued_packet) {
  if (writer_->IsWriteBlocked()) {
    visitor_->OnWriteBlocked(this);
    return false;
  }
  WriteResult result = writer_->WritePacket(
      queued_packet->packet()->data(),
      queued_packet->packet()->length(),
      queued_packet->server_address().address(),
      queued_packet->client_address());
  if (result.status == WRITE_STATUS_BLOCKED) {
    // If blocked and unbuffered, return false to retry sending.
    DCHECK(writer_->IsWriteBlocked());
    visitor_->OnWriteBlocked(this);
    return writer_->IsWriteBlockedDataBuffered();
  } else if (result.status == WRITE_STATUS_ERROR) {
    LOG(WARNING) << "Received unknown error while sending reset packet to "
                 << queued_packet->client_address().ToString() << ": "
                 << strerror(result.error_code);
  }
  return true;
}

void GoQuicTimeWaitListManager::SetConnectionIdCleanUpAlarm() {
  connection_id_clean_up_alarm_->Cancel();
  QuicTime now = helper_->GetClock()->ApproximateNow();
  QuicTime next_alarm_time = now;
  if (!connection_id_map_.empty()) {
    QuicTime oldest_connection_id =
        connection_id_map_.begin()->second.time_added;
    if (now.Subtract(oldest_connection_id) < kTimeWaitPeriod_) {
      next_alarm_time = oldest_connection_id.Add(kTimeWaitPeriod_);
    } else {
      LOG(ERROR) << "ConnectionId lingered for longer than kTimeWaitPeriod";
    }
  } else {
    // No connection_ids added so none will expire before kTimeWaitPeriod_.
    next_alarm_time = now.Add(kTimeWaitPeriod_);
  }

  connection_id_clean_up_alarm_->Set(next_alarm_time);
}

void GoQuicTimeWaitListManager::CleanUpOldConnectionIds() {
  QuicTime now = helper_->GetClock()->ApproximateNow();
  while (!connection_id_map_.empty()) {
    ConnectionIdMap::iterator it = connection_id_map_.begin();
    QuicTime oldest_connection_id = it->second.time_added;
    if (now.Subtract(oldest_connection_id) < kTimeWaitPeriod_) {
      break;
    }
    const QuicConnectionId connection_id = it->first;
    // This connection_id has lived its age, retire it now.
    delete it->second.close_packet;
    connection_id_map_.erase(it);
    visitor_->OnConnectionRemovedFromTimeWaitList(connection_id);
  }
  SetConnectionIdCleanUpAlarm();
}

}  // namespace net
