#ifndef __GO_STRUCTS_H__
#define __GO_STRUCTS_H__

struct GoIPEndPoint {
  unsigned char *ip_buf;
  size_t ip_length;
  uint16_t port;
};

#endif  // __GO_STRUCTS_H__
