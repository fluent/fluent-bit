#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_time.h>

#include "flb_tests_internal.h"

#define TIMEOUT             5
#define TEST_RECORD_01      "this is a test message"
#define TEST_RECORD_01_SIZE sizeof(TEST_RECORD_01) - 1

#define TEST_RECORD_02      "other type of message"
#define TEST_RECORD_02_SIZE sizeof(TEST_RECORD_02) - 1

static int check_clock(uint64_t timeout, struct flb_time *tm_start)
{
	struct flb_time tm_now;
	uint64_t diff;
	uint64_t now;
	uint64_t start;

    flb_time_get(&tm_now);
    now = flb_time_to_millisec(&tm_now);
    start = flb_time_to_millisec(tm_start);
    diff = now - start;

    if (!(TEST_CHECK(diff < timeout))) {
        TEST_MSG("clock error, unsuppresed log: now=%llu, start=%llu timeout=%llu(%llu), diff=%llu",
	         now, start, start+timeout, timeout, diff);
        return -1;
    }

    return 0;
}

static int update_and_check_clock(uint64_t timeout, int ret, struct flb_time *clock)
{
    int ret_val;

    if (ret == FLB_TRUE) {
        return 0;
    }

    /* false means timeout. check interval. */
    ret_val = check_clock(timeout, clock);
    flb_time_get(clock); /* reset clock */

    return ret_val;
}

static void cache_basic_timeout()
{
    int i;
    int ret;
    int ret_1;
    int ret_2;
    uint64_t timeout = 5000;
    struct flb_time clock1;
    struct flb_time clock2;
    struct flb_time start;
    struct flb_log_cache *cache;
    struct flb_log_cache_entry *entry;

    printf("\n");

    cache = flb_log_cache_create(10, 0);
    TEST_CHECK(cache == NULL);

    cache = flb_log_cache_create(5, 4);
    TEST_CHECK(cache != NULL);

    /* cache must be empty */
    entry = flb_log_cache_exists(cache, TEST_RECORD_01, TEST_RECORD_01_SIZE);
    TEST_CHECK(entry == NULL);

    /* upon trying to check for a suppress and if not found, it must be added */
    ret_1 = flb_log_cache_check_suppress(cache, TEST_RECORD_01, TEST_RECORD_01_SIZE);
    TEST_CHECK(ret_1 == FLB_FALSE);

    /* double check that it was added */
    entry = flb_log_cache_exists(cache, TEST_RECORD_01, TEST_RECORD_01_SIZE);
    TEST_CHECK(entry != NULL);

    printf("------------------------\n");

    /* reset */
    flb_log_cache_destroy(cache);

    /* create a new cache */
    cache = flb_log_cache_create(timeout, 4);
    TEST_CHECK(cache != NULL);

    flb_time_get(&clock1);
    ret_1 = flb_log_cache_check_suppress(cache, TEST_RECORD_01, TEST_RECORD_01_SIZE);

    flb_time_get(&clock2);
    ret_2 = flb_log_cache_check_suppress(cache, TEST_RECORD_02, TEST_RECORD_02_SIZE);

    TEST_CHECK(ret_1 == FLB_FALSE);
    TEST_CHECK(ret_2 == FLB_FALSE);

    sleep(1);


    for (i = 1, flb_time_get(&start); i < 10 && flb_time_to_millisec(&start)+(timeout*20) > time(NULL)*1000; i++) {
        ret_1 = flb_log_cache_check_suppress(cache, TEST_RECORD_01, TEST_RECORD_01_SIZE);
        ret = update_and_check_clock(timeout, ret_1, &clock1);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("update_and_check_clock for TEST_RECORD_01 failed. i=%d", i);
        }

        ret_2 = flb_log_cache_check_suppress(cache, TEST_RECORD_02, TEST_RECORD_02_SIZE);
        ret = update_and_check_clock(timeout, ret_2, &clock2);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("update_and_check_clock for TEST_RECORD_02 failed. i=%d", i);
        }

        sleep(1);
    }
    ret_1 = flb_log_cache_check_suppress(cache, TEST_RECORD_01, TEST_RECORD_01_SIZE);
    ret = update_and_check_clock(timeout, ret_1, &clock1);
    TEST_CHECK(ret == 0);

    ret_2 = flb_log_cache_check_suppress(cache, TEST_RECORD_02, TEST_RECORD_02_SIZE);
    ret = update_and_check_clock(timeout, ret_2, &clock2);
    TEST_CHECK(ret == 0);

    flb_log_cache_destroy(cache);
}

static void cache_one_slot()
{
    int i;
    int ret_1;
    int ret_2;
    struct flb_log_cache *cache;

    printf("\n");

    cache = flb_log_cache_create(2, 1);
    TEST_CHECK(cache != NULL);

    for (i = 0; i < 10; i++) {

        if (i == 0) {
            ret_1 = flb_log_cache_check_suppress(cache, TEST_RECORD_01, TEST_RECORD_01_SIZE);
            TEST_CHECK(ret_1 == FLB_FALSE);

            ret_1 = flb_log_cache_check_suppress(cache, TEST_RECORD_01, TEST_RECORD_01_SIZE);
            TEST_CHECK(ret_1 == FLB_TRUE);
        }
        else {
            ret_2 = flb_log_cache_check_suppress(cache, TEST_RECORD_02, TEST_RECORD_02_SIZE);
            ret_1 = flb_log_cache_check_suppress(cache, TEST_RECORD_01, TEST_RECORD_01_SIZE);

            TEST_CHECK(ret_1 == FLB_FALSE);
            TEST_CHECK(ret_2 == FLB_FALSE);
        }

        sleep(1);
    }

    flb_log_cache_destroy(cache);
}

TEST_LIST = {
    { "cache_basic_timeout" , cache_basic_timeout },
    { "cache_one_slot"      , cache_one_slot      },
    { 0 }
};
