/*
  libco.win (2008-01-28)
  authors: Nach, byuu
  license: public domain
*/

#define LIBCO_C
#include "libco.h"

#define WINVER 0x0400
#define _WIN32_WINNT 0x0400
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

static thread_local cothread_t co_active_ = 0;

static void __stdcall co_thunk(void* coentry) {
  ((void (*)(void))coentry)();
}

cothread_t co_active() {
  if(!co_active_) {
    ConvertThreadToFiber(0);
    co_active_ = GetCurrentFiber();
  }
  return co_active_;
}

cothread_t co_create(unsigned int heapsize, void (*coentry)(void),
                     size_t *out_size) {
  if(!co_active_) {
    ConvertThreadToFiber(0);
    co_active_ = GetCurrentFiber();
  }
  *out_size = heapsize;
  return (cothread_t)CreateFiber(heapsize, co_thunk, (void*)coentry);
}

void co_delete(cothread_t cothread) {
  DeleteFiber(cothread);
}

void co_switch(cothread_t cothread) {
  co_active_ = cothread;
  SwitchToFiber(cothread);
}

#ifdef __cplusplus
}
#endif
