#include <gperftools/heap-checker.h>
#include <gperftools/heap-profiler.h>
#include "heap_checker.h"
#include <stdlib.h>
#include <stdio.h>


int NoGlobalLeaks() {
#ifndef __APPLE__
	return HeapLeakChecker::NoGlobalLeaks();
#endif
}

void CancelGlobalCheck() {
#ifndef __APPLE__
	HeapLeakChecker::CancelGlobalCheck();
#endif
}

void ExtractProf() {
#ifndef __APPLE__
        const char* profile = GetHeapProfile();
        FILE *f = fopen("/tmp/prof", "w");
        fputs(profile, f);
        fclose(f);
        free(const_cast<char*>(profile));
#endif
}
