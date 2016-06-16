#ifndef __GO_STRUCTS_H__
#define __GO_STRUCTS_H__

#include <stdint.h>
#include <stddef.h>

struct ConnStat {
  uint64_t Conn_id;

  uint64_t Bytes_sent;  // Includes retransmissions, fec.
  uint64_t Packets_sent;
  // Non-retransmitted bytes sent in a stream frame.
  uint64_t Stream_bytes_sent;
  // Packets serialized and discarded before sending.
  uint64_t Packets_discarded;

  // These include version negotiation and public reset packets, which do not
  // have packet numbers or frame data.
  uint64_t Bytes_received;  // Includes duplicate data for a stream, fec.
  // Includes packets which were not processable.
  uint64_t Packets_received;
  // Excludes packets which were not processable.
  uint64_t Packets_processed;
  uint64_t Stream_bytes_received;  // Bytes received in a stream frame.

  uint64_t Bytes_retransmitted;
  uint64_t Packets_retransmitted;

  uint64_t Bytes_spuriously_retransmitted;
  uint64_t Packets_spuriously_retransmitted;
  // Number of packets abandoned as lost by the loss detection algorithm.
  uint64_t Packets_lost;

  // Number of packets sent in slow start.
  uint64_t Slowstart_packets_sent;
  // Number of packets lost exiting slow start.
  uint64_t Slowstart_packets_lost;

  uint64_t Packets_dropped;  // Duplicate or less than least unacked.
  size_t Crypto_retransmit_count;
  // Count of times the loss detection alarm fired.  At least one packet should
  // be lost when the alarm fires.
  size_t Loss_timeout_count;
  size_t Tlp_count;
  size_t Rto_count;  // Count of times the rto timer fired.

  int64_t Min_rtt_us;  // Minimum RTT in microseconds.
  int64_t Srtt_us;     // Smoothed RTT in microseconds.
  uint64_t Max_packet_size;
  uint64_t Max_received_packet_size;

  int64_t Estimated_bandwidth_bits_per_sec;

  // Reordering stats for received packets.
  // Number of packets received out of packet number order.
  uint64_t Packets_reordered;
  // Maximum reordering observed in packet number space.
  uint64_t Max_sequence_reordering;
  // Maximum reordering observed in microseconds
  int64_t Max_time_reordering_us;

  // The following stats are used only in TcpCubicSender.
  // The number of loss events from TCP's perspective.  Each loss event includes
  // one or more lost packets.
  uint32_t Tcp_loss_events;
};

struct GoQuicServerConfig {
  char* Server_config;
  int Server_config_len;

  char** Private_keys;
  int* Private_keys_len;
  uint32_t* Private_keys_tag;  // QuicTag == uint32_t
  int Num_of_keys;
};

struct GoSpdyHeader {
  int N;  // Size of header
  int* Keys_len;   // Length of each keys in header
  int* Values_len; // Length of each values in header

  // Used on C side to pass headers to Go.
  const char** Keys;
  const char** Values;
};

typedef int64_t GoPtr;

#endif  // __GO_STRUCTS_H__
