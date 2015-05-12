// +build cgo

package goquic

/*
#include <openssl/crypto.h>

extern int goquic_init_locks();
extern void goquic_thread_locking_callback(int, int, const char*, int);
extern unsigned long goquic_thread_id(void);

static int goquic_init_thread_callbacks() {
	// Source code referenced from: http://curl.haxx.se/libcurl/c/threaded-ssl.html
	int ret = goquic_init_locks();
	if (ret != 0) {
		return ret;
	}
	CRYPTO_set_locking_callback(goquic_thread_locking_callback);
	CRYPTO_set_id_callback(goquic_thread_id);
	return 0;
}

*/
import "C"

import "fmt"

func init() {
	ret := C.goquic_init_thread_callbacks()
	if ret != 0 {
		panic(fmt.Errorf("goquic_init_thread_callbacks failed with error node %d", ret))
	}
}
