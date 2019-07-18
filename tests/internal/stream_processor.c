/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/stream_processor/flb_sp.h>
#include <fluent-bit/stream_processor/flb_sp_window.h>

#include "flb_tests_internal.h"

#include <sys/types.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <fluent-bit/flb_compat.h>
#else
#include <unistd.h>
#endif

#define DATA_SAMPLES                                        \
    FLB_TESTS_DATA_PATH "/data/stream_processor/samples.mp"

#define DATA_SAMPLES_SUBKEYS                               \
    FLB_TESTS_DATA_PATH "/data/stream_processor/samples-subkeys.mp"

#define DATA_SAMPLES_HOPPING_WINDOW_PATH                   \
    FLB_TESTS_DATA_PATH "/data/stream_processor/samples-hw/"

#define MP_UOK MSGPACK_UNPACK_SUCCESS

static inline int float_cmp(double f1, double f2)
{
    double precision = 0.00001;

    if (((f1 - precision) < f2) &&
        ((f1 + precision) > f2)) {
        return 1;
    }
    else {
        return 0;
    }
}

static int file_to_buf(char *path, char **out_buf, size_t *out_size)
{
    int ret;
    long bytes;
    char *buf;
    FILE *fp;
    struct stat st;

    ret = stat(path, &st);
    if (ret == -1) {
        return -1;
    }

    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    buf = flb_malloc(st.st_size);
    if (!buf) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    bytes = fread(buf, st.st_size, 1, fp);
    if (bytes != 1) {
        flb_errno();
        flb_free(buf);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    *out_buf = buf;
    *out_size = st.st_size;

    return 0;
}

struct task_check {
    int id;
    int window_type;
    int window_val;
    int window_hop_val;
    char *name;
    char *exec;
    void (*cb_check)(int, struct task_check *, char *, size_t);

};

/* Helper functions */
static int mp_count_rows(char *buf, size_t size)
{
    int total = 0;
    size_t off = 0;
    msgpack_unpacked result;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, buf, size, &off) == MP_UOK) {
        total++;
    }

    msgpack_unpacked_destroy(&result);
    return total;
}

/* Count total number of keys considering all rows */
static int mp_count_keys(char *buf, size_t size)
{
    int keys = 0;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, buf, size, &off) == MP_UOK) {
        root = result.data;
        map = root.via.array.ptr[1];
        keys += map.via.map.size;
    }
    msgpack_unpacked_destroy(&result);

    return keys;
}

/* Lookup record/row number 'id' and check that 'key' matches 'val' */
static int mp_record_key_cmp(char *buf, size_t size,
                             int record_id, char *key,
                             int val_type, char *val_str, int64_t val_int64,
                             double val_f64)
{
    int i;
    int ret = FLB_FALSE;
    int id = 0;
    int k_len;
    int v_len;
    int keys = 0;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;
    msgpack_object k;
    msgpack_object v;

    k_len = strlen(key);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, buf, size, &off) == MP_UOK) {
        if (id != record_id) {
            id++;
            continue;
        }

        root = result.data;
        map = root.via.array.ptr[1];
        keys += map.via.map.size;

        for (i = 0; i < keys; i++) {
            k = map.via.map.ptr[i].key;
            v = map.via.map.ptr[i].val;

            if (k.type != MSGPACK_OBJECT_STR) {
                continue;
            }

            if (k.via.str.size != k_len) {
                continue;
            }

            if (strncmp(k.via.str.ptr, key, k_len) != 0) {
                continue;
            }

            /* at this point the key matched, now validate the expected value */
            if (val_type == MSGPACK_OBJECT_FLOAT) {
                if (v.type != MSGPACK_OBJECT_FLOAT32 &&
                    v.type != MSGPACK_OBJECT_FLOAT) {
                    msgpack_unpacked_destroy(&result);
                    return FLB_FALSE;
                }
            }
            else if (v.type != val_type) {
                msgpack_unpacked_destroy(&result);
                return FLB_FALSE;
            }

            switch (val_type) {
            case MSGPACK_OBJECT_STR:
                v_len = strlen(val_str);
                if (strncmp(v.via.str.ptr, val_str, v_len) == 0) {
                    ret = FLB_TRUE;
                }
                goto exit;
            case MSGPACK_OBJECT_POSITIVE_INTEGER:
                if (v.via.i64 == val_int64) {
                    ret = FLB_TRUE;
                }
                goto exit;
            case MSGPACK_OBJECT_FLOAT:
                if (float_cmp(v.via.f64, val_f64)) {
                    ret = FLB_TRUE;
                }
                else {
                    printf("double mismatch: %f exp %f\n",
                           v.via.f64, val_f64);
                }
                goto exit;
            };
        }
    }

exit:
    msgpack_unpacked_destroy(&result);
    return ret;
}

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

static void cb_select_groupby(int id, struct task_check *check,
                              char *buf, size_t size)
{
    int ret;

    /* Expect 1 row */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 2);

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

    /* MAX(id) is i9 for record 1 (bool=false)  */
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

/* Tests for 'test_select_keys' */
struct task_check select_keys_checks[] = {
    {
        0, 0, 0, 0,
        "select_all",
        "SELECT * FROM STREAM:FLB;",
        cb_select_all
    },
    {
        1, 0, 0, 0,
        "select_id",
        "SELECT id, word2 FROM STREAM:FLB;",
        cb_select_id
    },

    /* Conditionals */
    {
        2, 0, 0, 0,
        "select_cond_1",
        "SELECT * FROM STREAM:FLB WHERE bytes > 10.290;",
        cb_select_cond_1
    },
    {
        3, 0, 0, 0,
        "select_cond_2",
        "SELECT * FROM STREAM:FLB WHERE word2 = 'rlz' or word3 = 'rlz';",
        cb_select_cond_2
    },
    {
        4, 0, 0, 0,
        "select_cond_not_null",
        "SELECT * FROM STREAM:FLB WHERE word2 = 'rlz' and word3 IS NOT NULL;",
        cb_select_cond_not_null
    },
    {
        5, 0, 0, 0,
        "select_cond_null",
        "SELECT * FROM STREAM:FLB WHERE word3 IS NULL;",
        cb_select_cond_null
    },

    /* Aggregation functions */
    {
        6, 0, 0, 0,
        "select_aggr",
        "SELECT MIN(id), MAX(id), COUNT(*), SUM(bytes), AVG(bytes) " \
        "FROM STREAM:FLB;",
        cb_select_aggr,
    },
    {
        7, 0, 0, 0,
        "select_aggr_coount",
        "SELECT COUNT(*) " \
        "FROM STREAM:FLB;",
        cb_select_aggr_count,
    },
    {
        8, 0, 0, 0,
        "select_aggr_window_tumbling",
        "SELECT MIN(id), MAX(id), COUNT(*), SUM(bytes), AVG(bytes) " \
        "FROM STREAM:FLB WINDOW TUMBLING (1 SECOND);",
        cb_select_aggr,
    },
    {
        9, 0, 0, 0,
        "select_aggr_window_tumbling_groupby",
        "SELECT bool, MIN(id), MAX(id), COUNT(*), SUM(bytes), AVG(bytes) " \
        "FROM STREAM:FLB WINDOW TUMBLING (1 SECOND) WHERE word3 IS NOT NULL GROUP BY bool;",
        cb_select_groupby,
    },

    /* Time functions */
    {
        10, 0, 0, 0,
        "func_time_now",
        "SELECT NOW(), NOW() as tnow FROM STREAM:FLB WHERE bytes > 10;",
        cb_func_time_now,
    },
    {
        11, 0, 0, 0,
        "func_time_unix_timestamp",
        "SELECT UNIX_TIMESTAMP(), UNIX_TIMESTAMP() as ts " \
        "FROM STREAM:FLB WHERE bytes > 10;",
        cb_func_time_unix_timestamp,
    },

    /* Stream selection using Tag rules */
    {
        12, 0, 0, 0,
        "select_from_tag_error",
        "SELECT id FROM TAG:'no-matches' WHERE bytes > 10;",
        cb_select_tag_error,
    },
    {
        13, 0, 0, 0,
        "select_from_tag",
        "SELECT id FROM TAG:'samples' WHERE bytes > 10;",
        cb_select_tag_ok,
    },
    {
        14, 0, 0, 0,
        "@recond.contains",
        "SELECT id FROM TAG:'samples' WHERE bytes = 10 AND @record.contains(word2);",
        cb_record_contains,
    },
    {
        15, 0, 0, 0,
        "@recond.contains",
        "SELECT id FROM TAG:'samples' WHERE @record.contains(x);",
        cb_record_not_contains,
    }
};


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

static void cb_select_sub_record_contains(int id, struct task_check *check,
                                          char *buf, size_t size)
{
    int ret;

    /* Expect 5 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 5);
}

/* Tests for 'test_select_subkeys' */
struct task_check select_subkeys_checks[] = {
    {
        0, 0, 0, 0,
        "select_sub_blue",
        "SELECT * FROM STREAM:FLB WHERE map['sub1']['sub2']['color'] = 'blue';",
        cb_select_sub_blue
    },
    {
        1, 0, 0, 0,
        "select_sub_num",
        "SELECT * FROM STREAM:FLB WHERE map['sub1']['sub2'] = 123;",
        cb_select_sub_num
    },
    {
        2, 0, 0, 0,
        "select_sub_colors",
        "SELECT * FROM STREAM:FLB WHERE "            \
        "map['sub1']['sub2']['color'] = 'blue' OR "  \
        "map['sub1']['sub2']['color'] = 'red'  OR "  \
        "map['color'] = 'blue'; ",
        cb_select_sub_colors
    },
    {
        3, 0, 0, 0,
        "cb_select_sub_record_contains",
        "SELECT * FROM STREAM:FLB WHERE "            \
        "@record.contains(map['sub1']['sub3']) OR "  \
        "@record.contains(map['color']); ",
        cb_select_sub_record_contains
    },
    {   4, 0, 0, 0,
        "cb_select_sub_keys",
        "SELECT map['sub1']['sub2']['color'] FROM STREAM:FLB WHERE "    \
        "map['sub1']['sub2']['color'] = 'blue';",
        cb_select_sub_keys},
    {   5, 0, 0, 0,
        "cb_select_sum_sub_keys",
        "SELECT SUM(map['sub1']['sub2']) FROM STREAM:FLB WHERE "    \
        "map['sub1']['sub2'] = 123;",
        cb_select_sum_sub_keys},
    {   6, 0, 0, 0,
        "cb_select_avg_sub_keys",
        "SELECT AVG(map['sub1']['sub2']) FROM STREAM:FLB WHERE "    \
        "map['sub1']['sub2'] = 123;",
        cb_select_avg_sub_keys},
    {   7, 0, 0, 0,
        "cb_select_count_sub_keys",
        "SELECT COUNT(map['sub1']['sub2']) FROM STREAM:FLB WHERE "    \
        "map['sub1']['sub2'] = 123;",
        cb_select_count_sub_keys},
    {   8, 0, 0, 0,
        "cb_select_min_sub_keys",
        "SELECT MIN(map['sub1']['sub2']) FROM STREAM:FLB WHERE "  \
        "map['sub1']['sub2'] > 0;",
        cb_select_min_sub_keys},
    {   9, 0, 0, 0,
        "cb_select_max_sub_keys",
        "SELECT MAX(map['sub1']['sub3']) FROM STREAM:FLB WHERE "  \
        "map['sub1']['sub3'] > 0;",
        cb_select_max_sub_keys}
};

/* Tests to check syntactically valid/semantically invalid queries */
char *invalid_query_checks[] = {
    "SELECT id, MIN(id) FROM STREAM:FLB;",
    "SELECT *, COUNT(id) FROM STREAM:FLB;",
    "SELECT * FROM TAG:FLB WHERE bool = NULL ;",
    "SELECT * FROM TAG:FLB WHERE @record.some_random_func() ;",
    "SELECT id, MIN(id) FROM STREAM:FLB WINDOW TUMBLING (1 SECOND)" \
    " GROUP BY bool;",
    "SELECT *, COUNT(id) FROM STREAM:FLB WINDOW TUMBLING (1 SECOND)" \
    " GROUP BY bool;",
    "SELECT *, COUNT(bool) FROM STREAM:FLB WINDOW TUMBLING (1 SECOND)" \
    " GROUP BY bool;",
    "SELECT *, bool, COUNT(bool) FROM STREAM:FLB WINDOW TUMBLING (1 SECOND)" \
    " GROUP BY bool;"
};


static void invalid_queries()
{
    int i;
    int checks;
    struct flb_config *config;
    struct flb_sp *sp;
    struct flb_sp_task *task;

    /* Total number of checks for invalid */
    checks = sizeof(invalid_query_checks) / sizeof(char *);

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }
    mk_list_init(&config->inputs);
    mk_list_init(&config->stream_processor_tasks);

    sp = flb_sp_create(config);
    if (!sp) {
        flb_error("[sp test] cannot create stream processor context");
        flb_free(config);
        return;
    }

    for (i = 0; i < checks; i++) {
        task = flb_sp_task_create(sp, "invalid_query", invalid_query_checks[i]);
        TEST_CHECK(task == NULL);
    }

    flb_sp_destroy(sp);
    flb_free(config);
}

static void test_select_keys()
{
    int i;
    int checks;
    int ret;
    char *out_buf;
    size_t out_size;
    char *data_buf;
    size_t data_size;
    struct task_check *check;
    struct flb_config *config;
    struct flb_sp *sp;
    struct flb_sp_task *task;
#ifdef _WIN32
    WSADATA wsa_data;
#endif

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }
#ifdef _WIN32
    WSAStartup(0x0201, &wsa_data);
#endif
    mk_list_init(&config->inputs);
    mk_list_init(&config->stream_processor_tasks);

    config->evl = mk_event_loop_create(256);

    sp = flb_sp_create(config);
    if (!sp) {
        flb_error("[sp test] cannot create stream processor context");
        flb_free(config);
        return;
    }

    ret = file_to_buf(DATA_SAMPLES, &data_buf, &data_size);
    if (ret == -1) {
        flb_error("[sp test] cannot open DATA_SAMPLES file %s", DATA_SAMPLES);
        flb_free(config);
        return;
    }

    /* Total number of checks for select_keys */
    checks = (sizeof(select_keys_checks) / sizeof(struct task_check));

    /* Run every test */
    for (i = 0; i < checks; i++) {
        check = (struct task_check *) &select_keys_checks[i];

        task = flb_sp_task_create(sp, check->name, check->exec);
        if (!task) {
            flb_error("[sp test] wrong check '%s', fix it!", check->name);
            continue;
        }

        out_buf = NULL;
        out_size = 0;

        ret = flb_sp_test_do(sp, task,
                             "samples", 7,
                             data_buf, data_size,
                             &out_buf, &out_size);
        if (ret == -1) {
            flb_error("[sp test] error processing check '%s'", check->name);
            flb_sp_task_destroy(task);
            continue;
        }

        flb_sp_test_fd_event(task->window.fd, task, &out_buf, &out_size);

        flb_info("[sp test] id=%i, SQL => '%s'", check->id, check->exec);
        check->cb_check(check->id, check, out_buf, out_size);
        flb_pack_print(out_buf, out_size);
        flb_free(out_buf);
    }

    flb_free(data_buf);
    flb_sp_destroy(sp);
    mk_event_loop_destroy(config->evl);
    flb_free(config);
#ifdef _WIN32
    WSACleanup();
#endif
}

static void test_select_subkeys()
{
    int i;
    int checks;
    int ret;
    char *out_buf;
    size_t out_size;
    char *data_buf;
    size_t data_size;
    struct task_check *check;
    struct flb_config *config;
    struct flb_sp *sp;
    struct flb_sp_task *task;
#ifdef _WIN32
    WSADATA wsa_data;
#endif

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }
#ifdef _WIN32
    WSAStartup(0x0201, &wsa_data);
#endif
    mk_list_init(&config->inputs);
    mk_list_init(&config->stream_processor_tasks);

    config->evl = mk_event_loop_create(256);

    sp = flb_sp_create(config);
    if (!sp) {
        flb_error("[sp test] cannot create stream processor context");
        flb_free(config);
        return;
    }

    ret = file_to_buf(DATA_SAMPLES_SUBKEYS, &data_buf, &data_size);
    if (ret == -1) {
        flb_error("[sp test] cannot open DATA_SAMPLES file %s",
                  DATA_SAMPLES_SUBKEYS);
        flb_free(config);
        return;
    }

    /* Total number of checks for select_subkeys */
    checks = (sizeof(select_subkeys_checks) / sizeof(struct task_check));

    /* Run every test */
    for (i = 0; i < checks; i++) {
        check = (struct task_check *) &select_subkeys_checks[i];

        task = flb_sp_task_create(sp, check->name, check->exec);
        if (!task) {
            flb_error("[sp test] wrong check '%s', fix it!", check->name);
            continue;
        }

        out_buf = NULL;
        out_size = 0;

        ret = flb_sp_test_do(sp, task,
                             "samples", 7,
                             data_buf, data_size,
                             &out_buf, &out_size);
        if (ret == -1) {
            flb_error("[sp test] error processing check '%s'", check->name);
            flb_sp_task_destroy(task);
            continue;
        }

        flb_sp_test_fd_event(task->window.fd, task, &out_buf, &out_size);

        flb_info("[sp test] id=%i, SQL => '%s'", check->id, check->exec);
        check->cb_check(check->id, check, out_buf, out_size);
        flb_pack_print(out_buf, out_size);
        flb_free(out_buf);
    }

    flb_free(data_buf);
    flb_sp_destroy(sp);
    mk_event_loop_destroy(config->evl);
    flb_free(config);
#ifdef _WIN32
    WSACleanup();
#endif
}

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
                            NULL, 68, 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* Check AVG value result */
    ret = mp_record_key_cmp(buf, size, 0, "AVG(id)",
                            MSGPACK_OBJECT_FLOAT,
                            NULL, 0, 4.25);

    TEST_CHECK(ret == FLB_TRUE);
}

/* Tests for 'test_window' */
struct task_check window_checks[] = {
    {
        0, FLB_SP_WINDOW_TUMBLING, 5, 0,
        "window_5_seconds",
        "SELECT SUM(id), AVG(id) FROM STREAM:FLB WINDOW TUMBLING (5 SECOND) " \
        "WHERE word3 IS NOT NULL;",
        cb_window_5_second
    },
    {
        1, FLB_SP_WINDOW_HOPPING, 5, 2,
        "hopping_window_5_seconds",
        "SELECT SUM(id), AVG(id) FROM STREAM:FLB WINDOW HOPPING (5 SECOND, " \
        "ADVANCE BY 2 SECOND) WHERE word3 IS NOT NULL;",
        cb_hopping_window_5_second
    },
};

static void test_window()
{
    int i;
    int t;
    int checks;
    int ret;
    char datafile[100];
    char *out_buf = NULL;
    size_t out_size;
    char *data_buf = NULL;
    size_t data_size;
    struct task_check *check;
    struct flb_config *config;
    struct flb_sp *sp;
    struct flb_sp_task *task;
#ifdef _WIN32
    WSADATA wsa_data;
#endif

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }
#ifdef _WIN32
    WSAStartup(0x0201, &wsa_data);
#endif
    mk_list_init(&config->inputs);
    mk_list_init(&config->stream_processor_tasks);
    config->evl = mk_event_loop_create(256);

    sp = flb_sp_create(config);
    if (!sp) {
        flb_error("[sp test] cannot create stream processor context");
        flb_free(config);
        return;
    }

    /* Total number of checks for select_keys */
    checks = (sizeof(window_checks) / sizeof(struct task_check));

    /* Run every test */
    for (i = 0; i < checks; i++) {
        check = (struct task_check *) &window_checks[i];

        task = flb_sp_task_create(sp, check->name, check->exec);
        if (!task) {
            flb_error("[sp test] wrong check '%s', fix it!", check->name);
            continue;
        }

        out_buf = NULL;
        out_size = 0;

        if (check->window_type == FLB_SP_WINDOW_TUMBLING) {
            ret = file_to_buf(DATA_SAMPLES, &data_buf, &data_size);
            if (ret == -1) {
                flb_error("[sp test] cannot open DATA_SAMPLES file %s", DATA_SAMPLES);
                flb_free(config);
                return;
            }

            /* We ingest the buffer every second */
            for (t = 0; t < check->window_val; t++) {
                ret = flb_sp_test_do(sp, task,
                                     "samples", 7,
                                     data_buf, data_size,
                                     &out_buf, &out_size);
                if (ret == -1) {
                    flb_error("[sp test] error processing check '%s'",
                              check->name);
                    flb_sp_task_destroy(task);
                    return;
                }

                /* Sleep for 0.8 seconds, give some delta to the engine */
                usleep(800000);
            }

            flb_sp_test_fd_event(task->window.fd, task, &out_buf, &out_size);

            flb_info("[sp test] id=%i, SQL => '%s'", check->id, check->exec);
            check->cb_check(check->id, check, out_buf, out_size);
            flb_pack_print(out_buf, out_size);
            flb_free(out_buf);
        }
        else if (check->window_type == FLB_SP_WINDOW_HOPPING) {
            /* We ingest the buffer every second */
            task->window.fd = 0;
            task->window.fd_hop = 1;
            for (t = 0; t < check->window_val + check->window_hop_val; t++) {
                sprintf(datafile, "%s%d.mp",
                        DATA_SAMPLES_HOPPING_WINDOW_PATH, t + 1);
                ret = file_to_buf(datafile, &data_buf, &data_size);
                if (ret == -1) {
                    flb_error("[sp test] cannot open DATA_SAMPLES file %s", datafile);
                    flb_free(config);
                    return;
                }

                ret = flb_sp_test_do(sp, task,
                                     "samples", 7,
                                     data_buf, data_size,
                                     &out_buf, &out_size);
                if (ret == -1) {
                    flb_error("[sp test] error processing check '%s'",
                              check->name);
                    flb_sp_task_destroy(task);
                    return;
                }

                /* Sleep for 0.8 seconds, give some delta to the engine */
                usleep(800000);

                /* Hopping event */
                if ((t + 1) % check->window_hop_val == 0) {
                    flb_sp_test_fd_event(task->window.fd_hop, task, &out_buf,
                                         &out_size);
                }

                /* Window event */
                if ((t + 1) % check->window_val == 0 ||
                    (t + 1 > check->window_val && (t + 1 - check->window_val) % check->window_hop_val == 0)) {
                    flb_free(out_buf);
                    flb_sp_test_fd_event(task->window.fd, task, &out_buf, &out_size);
                }
                flb_free(data_buf);
                data_buf = NULL;
            }

            flb_info("[sp test] id=%i, SQL => '%s'", check->id, check->exec);
            check->cb_check(check->id, check, out_buf, out_size);
            flb_pack_print(out_buf, out_size);
            flb_free(out_buf);
        }

        flb_free(data_buf);
    }

    flb_sp_destroy(sp);
    mk_event_loop_destroy(config->evl);
    flb_free(config);
#ifdef _WIN32
    WSACleanup();
#endif
}

TEST_LIST = {
    { "invalid_queries", invalid_queries},
    { "select_keys",     test_select_keys},
    { "select_subkeys",  test_select_subkeys},
    { "window",          test_window},
    { NULL }
};
