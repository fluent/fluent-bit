#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

extern void *__libc_calloc(size_t count, size_t size);
extern void *__libc_realloc(void *pointer, size_t size);

static int fail_allocation(const char *kind, size_t size)
{
    const char *marker;
    const char *target;

    marker = getenv("INFLATION_FAILURE_MARKER");
    target = getenv(kind);
    if (marker != NULL && target != NULL && size == strtoull(target, NULL, 10) &&
        unlink(marker) == 0) {
        errno = ENOMEM;
        return 1;
    }
    return 0;
}

void *calloc(size_t count, size_t size)
{
    if (size == 1 && fail_allocation("INFLATION_CALLOC_SIZE", count)) {
        return NULL;
    }
    return __libc_calloc(count, size);
}

void *realloc(void *pointer, size_t size)
{
    if (fail_allocation("INFLATION_REALLOC_SIZE", size)) {
        return NULL;
    }
    return __libc_realloc(pointer, size);
}
