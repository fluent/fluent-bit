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

#include "flb_tests_internal.h"

#define DATA_SAMPLES FLB_TESTS_DATA_PATH "/data/stream_processor/samples.mp"

#define MP_UOK MSGPACK_UNPACK_SUCCESS

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

/* Callback functions to perform checks over results */
static void cb_select_all(int id, struct task_check *check,
                          char *buf, size_t size)
{
    int ret;

    /* Expect all 10 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 10);
}

/* Callback test: expect one key per record */
static void cb_select_id(int id, struct task_check *check,
                         char *buf, size_t size)
{
    int ret;

    /* Expect all 10 rows */
    ret = mp_count_rows(buf, size);
    TEST_CHECK(ret == 10);

    ret = mp_count_keys(buf, size);
    TEST_CHECK(ret == 12);
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

struct task_check select_keys_checks[] = {
    {
        0,
        "select_all",
        "SELECT * FROM STREAM:FLB;",
        cb_select_all
    },
    {
        1,
        "select_id",
        "SELECT id, word2 FROM STREAM:FLB;",
        cb_select_id
    },

    /* Conditionals */
    {
        2,
        "select_cond_1",
        "SELECT * FROM STREAM:FLB WHERE bytes > 10.290;",
        cb_select_cond_1
    },
    {
        3,
        "select_cond_2",
        "SELECT * FROM STREAM:FLB WHERE word2 = 'rlz' or word3 = 'rlz';",
        cb_select_cond_2
    },
};

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

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }
    mk_list_init(&config->inputs);

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

        flb_info("[sp test] id=%i, SQL => '%s'", check->id, check->exec);
        check->cb_check(check->id, check, out_buf, out_size);
        flb_pack_print(out_buf, out_size);
    }

    flb_free(data_buf);
    flb_sp_destroy(sp);
    flb_free(config);
}

TEST_LIST = {
    { "select_keys", test_select_keys},
    { NULL }
};
