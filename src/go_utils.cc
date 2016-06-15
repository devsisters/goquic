#include "go_utils.h"
#include "net/spdy/spdy_header_block.h"

namespace net {

GoSpdyHeader* CreateGoSpdyHeader(const SpdyHeaderBlock& header_block) {
  size_t N = header_block.size();
  GoSpdyHeader* hdr = new GoSpdyHeader;

  hdr->N = N;
  hdr->Keys = new const char*[N];
  hdr->Values = new const char*[N];
  hdr->Keys_len = new int[N];
  hdr->Values_len = new int[N];

  int idx = 0;
  for(auto it = header_block.begin(); it != header_block.end(); it++, idx++) {
    auto p = *it;
    hdr->Keys[idx] = p.first.data();
    hdr->Keys_len[idx] = p.first.length();
    hdr->Values[idx] = p.second.data();
    hdr->Values_len[idx] = p.second.length();
  }

  return hdr;
}

void DeleteGoSpdyHeader(GoSpdyHeader* go_header) {
  delete(go_header->Keys);
  delete(go_header->Keys_len);
  delete(go_header->Values);
  delete(go_header->Values_len);
  delete(go_header);
}

}

