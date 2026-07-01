#include <threads.h>

static int start_func(void *arg) {
        int iarg = *(int *)arg;
        return iarg;
}

void main(void) {
        thrd_t thr;
        int arg = 1;
        if (thrd_create(&thr, start_func, (void *)&arg) != thrd_success) {
                ;
        }
}
