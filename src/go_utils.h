#ifndef GO_UTILS_H_
#define GO_UTILS_H_

#include "go_structs.h"

namespace net {

class SpdyHeaderBlock;

GoSpdyHeader* CreateGoSpdyHeader(const SpdyHeaderBlock& header_block);
void DeleteGoSpdyHeader(GoSpdyHeader* go_header);

}

#endif   // GO_UTILS_H_
