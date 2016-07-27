#ifndef __HEAPCHECKER_
#define __HEAPCHECKER_

#ifdef __cplusplus
extern "C" {
#endif

int NoGlobalLeaks();
void CancelGlobalCheck();
void ExtractProf();

#ifdef __cplusplus
}
#endif

#endif
