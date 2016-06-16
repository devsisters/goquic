#ifndef GO_UTILS_H_
#define GO_UTILS_H_

#include "go_structs.h"

namespace net {

class SpdyHeaderBlock;

GoSpdyHeader* CreateGoSpdyHeader(const SpdyHeaderBlock& header_block);
void DeleteGoSpdyHeader(GoSpdyHeader* go_header);
void CreateSpdyHeaderBlock(SpdyHeaderBlock& block, int N, char* key_ptr, int* key_len, char* value_ptr, int* value_len);

}

#endif   // GO_UTILS_H_
