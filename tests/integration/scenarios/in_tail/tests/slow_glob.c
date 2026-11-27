/* Test-only Linux interposer: make a file age out during enumeration. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <glob.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int delay_match(const char *pattern, int result)
{
    const char *target;
    static int delayed;
    unsigned int seconds;

    target = getenv("TAIL_TEST_SLOW_GLOB_PATH");
    if (result == 0 && !delayed && target != NULL && strcmp(pattern, target) == 0) {
        delayed = 1;
        if (utimensat(AT_FDCWD, target, NULL, 0) != 0) {
            abort();
        }
        seconds = 4;
        while (seconds > 0) {
            seconds = sleep(seconds);
        }
    }
    return result;
}

int glob(const char *pattern, int flags, int (*errfunc)(const char *, int), glob_t *matches)
{
    int (*real_glob)(const char *, int, int (*)(const char *, int), glob_t *);

    real_glob = dlsym(RTLD_NEXT, "glob");
    return delay_match(pattern, real_glob(pattern, flags, errfunc, matches));
}

#ifdef __GLIBC__
int glob64(const char *pattern, int flags, int (*errfunc)(const char *, int), glob64_t *matches)
{
    int (*real_glob)(const char *, int, int (*)(const char *, int), glob64_t *);

    real_glob = dlsym(RTLD_NEXT, "glob64");
    return delay_match(pattern, real_glob(pattern, flags, errfunc, matches));
}
#endif
