#ifndef CMT_ATOMIC_H
#define CMT_ATOMIC_H

#include <stdint.h>

int cmt_atomic_initialize();
int cmt_atomic_compare_exchange(uint64_t *storage, uint64_t old_value, uint64_t new_value);
void cmt_atomic_store(uint64_t *storage, uint64_t new_value);
uint64_t cmt_atomic_load(uint64_t *storage);

#endif
