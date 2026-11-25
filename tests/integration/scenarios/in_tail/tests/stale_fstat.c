/* Test-only Linux interposer: hide an append from fstat without hiding its data. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int fstat(int fd, struct stat *st)
{
    int ret;
    int (*real_fstat)(int, struct stat *);
    ssize_t length;
    const char *target;
    const char *armed;
    const char *size;
    char descriptor[64];
    char path[PATH_MAX];
    static int reported;

    real_fstat = dlsym(RTLD_NEXT, "fstat");
    ret = real_fstat(fd, st);
    target = getenv("TAIL_TEST_STALE_TARGET");
    armed = getenv("TAIL_TEST_STALE_ARMED");
    size = getenv("TAIL_TEST_STALE_SIZE");
    if (ret != 0 || target == NULL || armed == NULL || size == NULL ||
        access(armed, F_OK) != 0) {
        return ret;
    }

    snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
    length = readlink(descriptor, path, sizeof(path) - 1);
    if (length < 0) {
        return ret;
    }
    path[length] = '\0';
    if (strcmp(path, target) == 0 && st->st_size > strtoll(size, NULL, 10)) {
        st->st_size = strtoll(size, NULL, 10);
        if (!reported) {
            fprintf(stderr, "tail test: stale size injected\n");
            reported = 1;
        }
    }
    return ret;
}
