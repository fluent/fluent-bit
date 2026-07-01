#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_lock.h>
#include <errno.h>

int flb_lock_init(flb_lock_t *lock)
{
    int result;

    result = pthread_mutex_init(lock, NULL);

    if (result != 0) {
        result = -1;
    }

    return result;
}

int flb_lock_destroy(flb_lock_t *lock)
{
    int result;

    result = pthread_mutex_destroy(lock);

    if (result != 0) {
        result = -1;
    }

    return result;
}

int flb_lock_acquire(flb_lock_t *lock,
                     size_t retry_limit,
                     size_t retry_delay)
{
    size_t retry_count;
    int    result;

    retry_count = 0;

    do {
        result = pthread_mutex_trylock(lock);

        if (result != 0) {
            if (result == EAGAIN || result == EBUSY) {
                if (retry_limit != FLB_LOCK_INFINITE_RETRY_LIMIT) {
                    retry_count++;
                }

                usleep(retry_delay);
            }
            else {
                break;
            }
        }
    }
    while (result != 0 &&
           retry_count < retry_limit);

    if (result != 0) {
        result = -1;
    }

    return result;
}

int flb_lock_release(pthread_mutex_t *lock,
                     size_t retry_limit,
                     size_t retry_delay)
{
    size_t retry_count;
    int    result;

    retry_count = 0;

    do {
        result = pthread_mutex_unlock(lock);

        if (result != 0) {
            if (result == EAGAIN) {
                if (retry_limit != FLB_LOCK_INFINITE_RETRY_LIMIT) {
                    retry_count++;
                }

                usleep(retry_delay);
            }
            else {
                break;
            }
        }
    }
    while (result != 0 &&
           retry_count < retry_limit);

    if (result != 0) {
        result = -1;
    }

    return result;
}
