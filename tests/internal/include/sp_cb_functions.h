#include "sp_helpers.h"

#ifndef FLB_TEST_CP_FUNCTIONS
#define FLB_TEST_CP_FUNCTIONS

/* Callback functions to perform checks over results */
static void cb_select_all(int id, struct task_check *check,
                          char *buf, size_t size)
{
    int ret;

    /* Expect all 11 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 11);
}

/* Callback test: expect one key per record */
static void cb_select_id(int id, struct task_check *check,
                         char *buf, size_t size)
{
    int ret;

    /* Expect all 11 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 11);

    ret = mp_count_keys(buf, size);
    TEST_CHECK(ret == 13);
}

static void cb_select_cond_1(int id, struct task_check *check,
                             char *buf, size_t size)
{
    int ret;

    /* Expect 1 row */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 1);
}

static void cb_select_cond_2(int id, struct task_check *check,
                             char *buf, size_t size)
{
    int ret;

    /* Expect 2 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 2);
}

static void cb_select_cond_not_null(int id, struct task_check *check,
                                    char *buf, size_t size)
{
    int ret;

    /* Expect 1 row */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 1);
}

static void cb_select_cond_null(int id, struct task_check *check,
                                char *buf, size_t size)
{
    int ret;

    /* Expect 1 row */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 1);
}

static void cb_select_not_equal_1(int id, struct task_check *check,
                                  char *buf, size_t size)
{
    int ret;

    /* Expect 1 row */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 2);
}

static void cb_select_not_equal_2(int id, struct task_check *check,
                                  char *buf, size_t size)
{
    int ret;

    /* Expect 2 row */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 2);
}

static void cb_select_aggr_count(int id, struct task_check *check,
                                 char *buf, size_t size)
{
    int ret;

    /* Expect 1 row */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 1);

    /* COUNT(*) is 11 */
    ret = mp_record_key_cmp(buf, size,
                            0, "COUNT(*)",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 11, 0);
    TEST_CHECK(ret == FLB_TRUE);
}

static void cb_func_time_now(int id, struct task_check *check,
                             char *buf, size_t size)
{
    int ret;
    char tmp[32];
    struct tm *local;
    time_t now = time(NULL);

    local = localtime(&now);
    strftime(tmp, sizeof(tmp) - 1, "%Y-%m-%d %H:%M:%S", local);

    /* Expect 2 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 2);

    /* NOW() */
    ret = mp_record_key_cmp(buf, size,
                            0, "NOW()",
                            MSGPACK_OBJECT_STR,
                            tmp, 0, 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* tnow */
    ret = mp_record_key_cmp(buf, size,
                            1, "tnow",
                            MSGPACK_OBJECT_STR,
                            tmp, 0, 0);
    TEST_CHECK(ret == FLB_TRUE);
}

static void cb_func_time_unix_timestamp(int id, struct task_check *check,
                                        char *buf, size_t size)
{
    int ret;
    time_t now = time(NULL);

    /* Expect 2 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 2);

    /* UNIX_TIMESTAMP() */
    ret = mp_record_key_cmp(buf, size,
                            0, "UNIX_TIMESTAMP()",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, now, 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* tnow */
    ret = mp_record_key_cmp(buf, size,
                            1, "ts",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, now, 0);
    TEST_CHECK(ret == FLB_TRUE);
}

/* No records must be selected */
static void cb_select_tag_error(int id, struct task_check *check,
                                char *buf, size_t size)
{
    int ret;

    TEST_CHECK(buf == NULL && size == 0);

    /* no records expected */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 0);
}

/* No records must be selected */
static void cb_select_tag_ok(int id, struct task_check *check,
                             char *buf, size_t size)
{
    int ret;

    TEST_CHECK(buf != NULL && size > 0);

    /* 2 records expected */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 2);
}

static void cb_record_contains(int id, struct task_check *check,
                               char *buf, size_t size)
{
    int ret;

    /* Expect 2 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 2);
}

static void cb_record_not_contains(int id, struct task_check *check,
                                   char *buf, size_t size)
{
    int ret;

    /* Expect 0 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 0);
}

static void cb_select_and_or_precedence(int id, struct task_check *check,
                                        char *buf, size_t size)
{
    int ret;

    /* Expect all 11 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK_(ret == 11, "expected 11 rows but got %d", ret);
}

static void cb_select_not_or_precedence(int id, struct task_check *check,
                                        char *buf, size_t size)
{
    int ret;

    /* Expect all 11 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK_(ret == 11, "expected 11 rows but got %d", ret);
}

static void cb_select_not_and_precedence(int id, struct task_check *check,
                                         char *buf, size_t size)
{
    int ret;

    /* Expect 0 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK_(ret == 0, "expected 0 rows but got %d", ret);
}

/* Callback functions to perform checks over results */
static void cb_select_sub_blue(int id, struct task_check *check,
                               char *buf, size_t size)
{
    int ret;

    /* Expect 1 row */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 1);
}

static void cb_select_sub_num(int id, struct task_check *check,
                              char *buf, size_t size)
{
    int ret;

    /* Expect 2 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 2);
}

static void cb_select_sub_colors(int id, struct task_check *check,
                                 char *buf, size_t size)
{
    int ret;

    /* Expect 3 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 3);
}

static void cb_select_sub_record_contains(int id, struct task_check *check,
                                          char *buf, size_t size)
{
    int ret;

    /* Expect 5 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 5);
}

static void cb_select_sub_keys(int id, struct task_check *check,
                               char *buf, size_t size)
{
    int ret;

    /* Expect 1 row */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 1);

    ret = mp_record_key_cmp(buf, size,
                            0, "map['sub1']['sub2']['color']",
                            MSGPACK_OBJECT_STR,
                            "blue", 0, 0);
    TEST_CHECK(ret == FLB_TRUE);
}

static void cb_select_sum_sub_keys(int id, struct task_check *check,
                                   char *buf, size_t size)
{
    int ret;

    /* Expect 1 row */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 1);

    ret = mp_record_key_cmp(buf, size,
                            0, "SUM(map['sub1']['sub2'])",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 246, 0);
    TEST_CHECK(ret == FLB_TRUE);
}

static void cb_select_avg_sub_keys(int id, struct task_check *check,
                                   char *buf, size_t size)
{
    int ret;

    /* Expect 1 row */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 1);

    ret = mp_record_key_cmp(buf, size,
                            0, "AVG(map['sub1']['sub2'])",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 123.0);
    TEST_CHECK(ret == FLB_TRUE);
}

static void cb_select_count_sub_keys(int id, struct task_check *check,
                                     char *buf, size_t size)
{
    int ret;

    /* Expect 1 row */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 1);

    ret = mp_record_key_cmp(buf, size,
                            0, "COUNT(map['sub1']['sub2'])",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 2, 0);
    TEST_CHECK(ret == FLB_TRUE);
}

static void cb_select_min_sub_keys(int id, struct task_check *check,
                                   char *buf, size_t size)
{
    int ret;

    /* Expect 1 row */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 1);

    ret = mp_record_key_cmp(buf, size,
                            0, "MIN(map['sub1']['sub2'])",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 123, 0);
    TEST_CHECK(ret == FLB_TRUE);
}

static void cb_select_max_sub_keys(int id, struct task_check *check,
                                   char *buf, size_t size)
{
    int ret;

    /* Expect 1 row */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 1);

    ret = mp_record_key_cmp(buf, size,
                            0, "MAX(map['sub1']['sub3'])",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 100);
    TEST_CHECK(ret == FLB_TRUE);
}

static void cb_select_sum_sub_keys_group_by(int id, struct task_check *check,
                                            char *buf, size_t size)
{
    int ret;

    /* Expect 3 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 3);

    ret = mp_record_key_cmp(buf, size,
                            0, "SUM(map['sub1']['sub3'])",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 105.5);
    TEST_CHECK(ret == FLB_TRUE);
}

static void cb_select_sum_sub_keys_group_by_2(int id, struct task_check *check,
                                              char *buf, size_t size)
{
    int ret;

    /* Expect 3 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 3);

    ret = mp_record_key_cmp(buf, size,
                            0, "SUM(map['sub1']['sub3'])",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 105.5);
    TEST_CHECK(ret == FLB_TRUE);
}

static void cb_select_sum_sub_keys_group_by_3(int id, struct task_check *check,
                                              char *buf, size_t size)
{
    int ret;

    /* Expect 3 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 3);

    ret = mp_record_key_cmp(buf, size,
                            0, "SUM(map['sub1']['sub3'])",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 100, 0);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_record_key_cmp(buf, size,
                            1, "SUM(map['sub1']['sub3'])",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 11);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_record_key_cmp(buf, size,
                            2, "SUM(map['sub1']['sub3'])",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 5.5);
    TEST_CHECK(ret == FLB_TRUE);
}


static void cb_forecast_tumbling_window(int id, struct task_check *check,
                                        char *buf, size_t size)
{
    int ret;

    /* Expect one record only */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 1);

    /* Check SUM value result */
    ret = mp_record_key_cmp(buf, size, 0, "TIMESERIES_FORECAST(usage)",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 310.0);
    TEST_CHECK(ret == FLB_TRUE);

    /* Check AVG value result */
    ret = mp_record_key_cmp(buf, size, 0, "AVG(usage)",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 60.0);

    TEST_CHECK(ret == FLB_TRUE);
}

/* Callback functions to perform checks over results */
static void cb_snapshot_create(int id, struct task_check *check,
                               char *buf, size_t size)
{
    int ret;

    ret = mp_count_rows(buf, size);
    /* Snapshot doesn't return anything */
    TEST_CHECK(ret == 0);
};

static void cb_snapshot_purge(int id, struct task_check *check,
                              char *buf, size_t size)
{
    int ret;

    /* Expect 5 rows, as set in snapshot query */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 5);
};

static void cb_snapshot_purge_time(int id, struct task_check *check,
                                   char *buf, size_t size)
{
    int ret;

    /* Expect 11 rows, as set in snapshot query */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 11);
};

static void cb_window_5_second(int id, struct task_check *check,
                               char *buf, size_t size)
{
    int ret;

    /* Expect one record only */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 1);

    /* Check SUM value result */
    ret = mp_record_key_cmp(buf, size, 0, "SUM(id)",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 225, 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* Check AVG value result */
    ret = mp_record_key_cmp(buf, size, 0, "AVG(id)",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 4.5);

    TEST_CHECK(ret == FLB_TRUE);
}

static void cb_select_aggr(int id, struct task_check *check,
                           char *buf, size_t size)
{
    int ret;

    /* Expect 1 row */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 1);

    /* MIN(id) is 0 */
    ret = mp_record_key_cmp(buf, size,
                            0, "MIN(id)",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 0, 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* MAX(id) is 10 */
    ret = mp_record_key_cmp(buf, size,
                            0, "MAX(id)",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 10, 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* COUNT(*) is 11 */
    ret = mp_record_key_cmp(buf, size,
                            0, "COUNT(*)",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 11, 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* SUM(bytes) is 110.50 */
    ret = mp_record_key_cmp(buf, size,
                            0, "SUM(bytes)",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 110.50);
    TEST_CHECK(ret == FLB_TRUE);

    /* AVG(bytes) is 10.04545 */
    ret = mp_record_key_cmp(buf, size,
                            0, "AVG(bytes)",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 10.045455);
    TEST_CHECK(ret == FLB_TRUE);
}

static void cb_select_groupby(int id, struct task_check *check,
                              char *buf, size_t size)
{
    int ret;

    /* Expect 1 row */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 2);

    /* bool is 1 for record 0 (bool=true) */
    ret = mp_record_key_cmp(buf, size,
                            0, "bool",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 1, 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* bool is 0 for record 1 (bool=false) */
    ret = mp_record_key_cmp(buf, size,
                            1, "bool",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 0, 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* MIN(id) is 0 for record 0 (bool=true) */
    ret = mp_record_key_cmp(buf, size,
                            0, "MIN(id)",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 0, 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* MIN(id) is 6 for record 1 (bool=false)  */
    ret = mp_record_key_cmp(buf, size,
                            1, "MIN(id)",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 6, 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* MAX(id) is 8 for record 0 (bool=true)  */
    ret = mp_record_key_cmp(buf, size,
                            0, "MAX(id)",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 8, 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* MAX(id) is 9 for record 1 (bool=false)  */
    ret = mp_record_key_cmp(buf, size,
                            1, "MAX(id)",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 9, 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* COUNT(*) is 8 for record 0 (bool=true) */
    ret = mp_record_key_cmp(buf, size,
                            0, "COUNT(*)",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 8, 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* COUNT(*) is 2 for record 1 (bool=false) */
    ret = mp_record_key_cmp(buf, size,
                            1, "COUNT(*)",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 2, 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* SUM(bytes) is 80.0 for record 0 (bool=true) */
    ret = mp_record_key_cmp(buf, size,
                            0, "SUM(bytes)",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 80.0);
    TEST_CHECK(ret == FLB_TRUE);

    /* SUM(bytes) is 20.50 for record 1 (bool=false) */
    ret = mp_record_key_cmp(buf, size,
                            1, "SUM(bytes)",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 20.50);
    TEST_CHECK(ret == FLB_TRUE);

    /* AVG(bytes) is 10.0 for record 0 (bool=true) */
    ret = mp_record_key_cmp(buf, size,
                            0, "AVG(bytes)",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 10.0);
    TEST_CHECK(ret == FLB_TRUE);

    /* AVG(bytes) is 10.25 for record 1 (bool=false) */
    ret = mp_record_key_cmp(buf, size,
                            1, "AVG(bytes)",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 10.25);
    TEST_CHECK(ret == FLB_TRUE);
}

static void cb_hopping_window_5_second(int id, struct task_check *check,
                                       char *buf, size_t size)
{
    int ret;

    /* Expect one record only */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 1);

    /* Check SUM value result */
    ret = mp_record_key_cmp(buf, size, 0, "SUM(id)",
                            MSGPACK_OBJECT_POSITIVE_INTEGER,
                            NULL, 266, 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* Check AVG value result */
    ret = mp_record_key_cmp(buf, size, 0, "AVG(id)",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 16.625);

    TEST_CHECK(ret == FLB_TRUE);
}

static void cb_forecast_hopping_window(int id, struct task_check *check,
                                       char *buf, size_t size)
{
    int ret;

    /* Expect one record only */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 1);

    /* Check SUM value result */
    ret = mp_record_key_cmp(buf, size, 0, "TIMESERIES_FORECAST(usage)",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 460.0);
    TEST_CHECK(ret == FLB_TRUE);

    /* Check AVG value result */
    ret = mp_record_key_cmp(buf, size, 0, "AVG(usage)",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 175.0);

    TEST_CHECK(ret == FLB_TRUE);
}

#endif
