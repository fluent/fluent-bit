#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>

#include "flb_tests_internal.h"

#define TIMEOUT             5
#define TEST_RECORD_01      "this is a test message"
#define TEST_RECORD_01_SIZE sizeof(TEST_RECORD_01) - 1

#define TEST_RECORD_02      "other type of message"
#define TEST_RECORD_02_SIZE sizeof(TEST_RECORD_02) - 1

static void cache_basic_timeout()
{
    int i;
    int ret_1;
    int ret_2;
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
    cache = flb_log_cache_create(5, 4);
    TEST_CHECK(cache != NULL);

    for (i = 0; i < 10; i++) {
        ret_1 = flb_log_cache_check_suppress(cache, TEST_RECORD_01, TEST_RECORD_01_SIZE);
        ret_2 = flb_log_cache_check_suppress(cache, TEST_RECORD_02, TEST_RECORD_02_SIZE);

        if (i == 0) {
            TEST_CHECK(ret_1 == FLB_FALSE);
            TEST_CHECK(ret_2 == FLB_FALSE);
        }
        else if (i >= 1 && i < 5) {
            TEST_CHECK(ret_1 == FLB_TRUE);
            TEST_CHECK(ret_2 == FLB_TRUE);
        }
        else if (i == 5) {
            TEST_CHECK(ret_1 == FLB_FALSE);
            TEST_CHECK(ret_2 == FLB_FALSE);
        }
        else {
            TEST_CHECK(ret_1 == FLB_TRUE);
            TEST_CHECK(ret_2 == FLB_TRUE);
        }

        sleep(1);
    }

    ret_1 = flb_log_cache_check_suppress(cache, TEST_RECORD_01, TEST_RECORD_01_SIZE);
    TEST_CHECK(ret_1 == FLB_FALSE);

    ret_2 = flb_log_cache_check_suppress(cache, TEST_RECORD_02, TEST_RECORD_02_SIZE);
    TEST_CHECK(ret_2 == FLB_FALSE);

    flb_log_cache_destroy(cache);
}

static void cache_one_slot()
{
    int i;
    int ret_1;
    int ret_2;
    struct flb_log_cache *cache;
    struct flb_log_cache_entry *entry;

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
