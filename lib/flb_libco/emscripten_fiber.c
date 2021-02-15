#define LIBCO_C
#include "libco.h"

#define _BSD_SOURCE
#define _XOPEN_SOURCE 500
#include <stdlib.h>
#include <emscripten/fiber.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*thread_cb)();

// Todo: dynamic stack size
typedef struct {
    emscripten_fiber_t context;
    char *asyncify_stack;
    char *c_stack;
} Fiber;

static inline void thread_entry(void *entrypoint) {
  ((thread_cb)entrypoint)();
}

static Fiber main_fiber;
static Fiber* running_fiber = 0;

void init_main_fiber() {
  main_fiber.asyncify_stack = (char*)malloc(4096 * sizeof(char));
  emscripten_fiber_init_from_current_context(&main_fiber.context, main_fiber.asyncify_stack, 4096);
  running_fiber = &main_fiber;
}

cothread_t co_active() {
  if(!running_fiber) init_main_fiber();

  return (cothread_t)running_fiber;
}

cothread_t co_derive(void* memory, unsigned int heapsize, void (*coentry)(void)) {
  if(!running_fiber) init_main_fiber();

  Fiber* fiber = malloc(sizeof(Fiber));
  fiber->c_stack = (char*) memory;
  fiber->asyncify_stack = (char*) malloc(heapsize * sizeof(char));

  emscripten_fiber_init(&fiber->context, thread_entry, coentry, fiber->c_stack, heapsize, fiber->asyncify_stack, heapsize);

  return (cothread_t)fiber;
}

cothread_t co_create(unsigned int heapsize, void (*coentry)(void), size_t *out_size) {
  if(!running_fiber) init_main_fiber();

  Fiber* fiber = malloc(sizeof(Fiber));
  fiber->c_stack = (char*)malloc(heapsize * sizeof(char));
  fiber->asyncify_stack = (char*)malloc(heapsize * sizeof(char));

  emscripten_fiber_init(&fiber->context, thread_entry, coentry, fiber->c_stack, heapsize, fiber->asyncify_stack, heapsize);
  *out_size = heapsize; 
  return (cothread_t)fiber;
}

void co_delete(cothread_t cothread) {
  if(cothread) {
    free(cothread);
  }
}

void co_switch(cothread_t cothread) {
  Fiber* old_fiber = running_fiber;
  running_fiber = (Fiber*)cothread;
  
  emscripten_fiber_swap(&old_fiber->context, &running_fiber->context);
}

int co_serializable() {
  return 0;
}

#ifdef __cplusplus
}
#endif
