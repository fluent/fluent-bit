/* RISC-V coroutine stack regression tests. SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>
#include <libco.h>

#include <stdio.h>
#include <stdlib.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); abort(); \
} } while (0)

static cothread_t caller;
static int resumed;

static void entrypoint(void)
{
    resumed = 1;
    co_switch(caller);
    resumed = 2;
    co_switch(caller);
}

int main(void)
{
    unsigned int sizes[] = {0, 1, 15, 16, 17, 512, 4096};
    size_t index;
    size_t allocated;
    size_t minimum;
    cothread_t coroutine;

    caller = co_active();
    coroutine = co_create(0, entrypoint, &minimum);
    CHECK(coroutine != NULL);
    CHECK(minimum >= 512);
    co_delete(coroutine);

    for (index = 0; index < sizeof(sizes) / sizeof(sizes[0]); index++) {
        coroutine = co_create(sizes[index], entrypoint, &allocated);
        CHECK(coroutine != NULL);
        CHECK(allocated == minimum + (((size_t) sizes[index] + 15) & ~(size_t) 15));
        CHECK(((uintptr_t) coroutine + allocated) % 16 == 0);
        resumed = 0;
        co_switch(coroutine);
        CHECK(resumed == 1);
        co_switch(coroutine);
        CHECK(resumed == 2);
        co_delete(coroutine);
    }
    return 0;
}
