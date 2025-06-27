/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/stream_processor/flb_sp.h>
#include <fluent-bit/stream_processor/flb_sp_parser.h>
#include <fluent-bit/stream_processor/flb_sp_stream.h>
#include <fluent-bit/stream_processor/flb_sp_window.h>
#include <msgpack.h>

#include "flb_tests_internal.h"
#include "include/sp_invalid_queries.h"
#include "include/sp_select_keys.h"
#include "include/sp_select_subkeys.h"
#include "include/sp_window.h"
#include "include/sp_snapshot.h"

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

int flb_sp_fd_event_test(int fd, struct flb_sp_task *task, struct sp_buffer *out_buf)
{
    char *tag = NULL;
    int tag_len = 0;

    if (task->window.type != FLB_SP_WINDOW_DEFAULT) {
        if (fd == task->window.fd) {
            if (task->window.records > 0) {
                /* find input tag from task source */
                package_results(tag, tag_len, &out_buf->buffer, &out_buf->size, task);
                if (task->stream) {
                    flb_sp_stream_append_data(out_buf->buffer, out_buf->size, task->stream);
                }
                else {
                    flb_pack_print(out_buf->buffer, out_buf->size);
                }
            }

            flb_sp_window_prune(task);
        }
        else if (fd == task->window.fd_hop) {
            sp_process_hopping_slot(tag, tag_len, task);
        }
    }

    return 0;
}

/*
 * Do data processing for internal unit tests, no engine required, set
 * results on out_data/out_size variables.
 */
int flb_sp_do_test(struct flb_sp *sp, struct flb_sp_task *task,
                   const char *tag, int tag_len,
                   struct sp_buffer *data_buf, struct sp_buffer *out_buf)
{
    int ret;
    int records;
    struct flb_sp_cmd *cmd;

    cmd = task->cmd;
    if (cmd->source_type == FLB_SP_TAG) {
        ret = flb_router_match(tag, tag_len, cmd->source_name, NULL);
        if (ret == FLB_FALSE) {
            out_buf->buffer = NULL;
            out_buf->size = 0;
            return 0;
        }
    }

    if (task->aggregate_keys == FLB_TRUE) {
        ret = sp_process_data_aggr(data_buf->buffer, data_buf->size,
                                   tag, tag_len,
                                   task, sp, FLB_TRUE);
        if (ret == -1) {
            flb_error("[sp] error error processing records for '%s'",
                      task->name);
            return -1;
        }

        if (flb_sp_window_populate(task, data_buf->buffer, data_buf->size) == -1) {
            flb_error("[sp] error populating window for '%s'",
                      task->name);
            return -1;
        }
        if (task->window.type == FLB_SP_WINDOW_DEFAULT || task->window.type == FLB_SP_WINDOW_TUMBLING) {
            package_results(tag, tag_len, &out_buf->buffer, &out_buf->size, task);
        }

        records = task->window.records;
    }
    else {
        ret = sp_process_data(tag, tag_len,
                              data_buf->buffer, data_buf->size,
                              &out_buf->buffer, &out_buf->size,
                              task, sp);
        if (ret == -1) {
            flb_error("[sp] error processing records for '%s'",
                      task->name);
            return -1;
        }
        records = ret;
    }

    if (records == 0) {
        out_buf->buffer = NULL;
        out_buf->size = 0;
        return 0;
    }

    return 0;
}

/* this function reads the content of a file containing MessagePack data
   into an input buffer
*/
static int file_to_buf(char *path, struct sp_buffer *out_buf)
{
    char *buf;
    int ret;
    long bytes;
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
    out_buf->buffer = buf;
    out_buf->size = st.st_size;

    return 0;
}

static void invalid_queries()
{
    int i;
    int checks;
    struct flb_config *config;
    struct flb_sp *sp;
    struct flb_sp_task *task;

    flb_init_env();

    /* Total number of checks for invalid queries */
    checks = sizeof(invalid_query_checks) / sizeof(char *);

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return;
    }

    mk_list_init(&config->inputs);
    mk_list_init(&config->stream_processor_tasks);

    /* Create a stream processor context */
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
    struct sp_buffer data_buf;
    struct sp_buffer out_buf;
    struct flb_config *config;
    struct flb_sp *sp;
    struct task_check *check;
    struct flb_sp_task *task;
#ifdef _WIN32
    WSADATA wsa_data;
#endif

    flb_init_env();

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

   /* Create event loop */
    config->evl = mk_event_loop_create(256);

    /* Create a stream processor context */
    sp = flb_sp_create(config);
    if (!sp) {
        flb_error("[sp test] cannot create stream processor context");
        flb_free(config);
        return;
    }

    ret = file_to_buf(DATA_SAMPLES, &data_buf);
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

        out_buf.buffer = NULL;

        ret = flb_sp_do_test(sp, task,
                             "samples", strlen("samples"),
                             &data_buf, &out_buf);
        if (ret == -1) {
            flb_error("[sp test] error processing check '%s'", check->name);
            flb_sp_task_destroy(task);
            continue;
        }

        /* */
        flb_sp_fd_event_test(task->window.fd, task, &out_buf);

        flb_info("[sp test] id=%i, SQL => '%s'", check->id, check->exec);
        check->cb_check(check->id, check, out_buf.buffer, out_buf.size);
        flb_pack_print(out_buf.buffer, out_buf.size);
        flb_free(out_buf.buffer);
    }

    flb_free(data_buf.buffer);
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
    struct sp_buffer out_buf;
    struct sp_buffer data_buf;
    struct task_check *check;
    struct flb_config *config;
    struct flb_sp *sp;
    struct flb_sp_task *task;
#ifdef _WIN32
    WSADATA wsa_data;
#endif

    flb_init_env();

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

    ret = file_to_buf(DATA_SAMPLES_SUBKEYS, &data_buf);
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

        out_buf.buffer = NULL;
        out_buf.size = 0;

        ret = flb_sp_do_test(sp, task,
                             "samples", strlen("samples"),
                             &data_buf, &out_buf);
        if (ret == -1) {
            flb_error("[sp test] error processing check '%s'", check->name);
            flb_sp_task_destroy(task);
            continue;
        }

        flb_sp_fd_event_test(task->window.fd, task, &out_buf);

        flb_info("[sp test] id=%i, SQL => '%s'", check->id, check->exec);
        check->cb_check(check->id, check, out_buf.buffer, out_buf.size);
        flb_pack_print(out_buf.buffer, out_buf.size);
        flb_free(out_buf.buffer);
    }

    flb_free(data_buf.buffer);
    flb_sp_destroy(sp);
    mk_event_loop_destroy(config->evl);
    flb_free(config);
#ifdef _WIN32
    WSACleanup();
#endif
}

void set_record_timestamps(struct sp_buffer *data_buf, double *record_timestamp)
{
    /* unpacker variables */
    int ok;
    size_t off = 0;
    msgpack_object root;
    msgpack_object map;
    msgpack_unpacked result;
    struct flb_time tm;

    /* packer variables */
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    ok = MSGPACK_UNPACK_SUCCESS;
    msgpack_unpacked_init(&result);

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Iterate incoming records */
    while (msgpack_unpack_next(&result, data_buf->buffer, data_buf->size, &off) == ok) {
        root = result.data;

        map = root.via.array.ptr[1];

        msgpack_pack_array(&mp_pck, 2);
        flb_time_set(&tm, *record_timestamp, 0);
        flb_time_append_to_msgpack(&tm, &mp_pck, 0);
        msgpack_pack_object(&mp_pck, map);

        *record_timestamp = *record_timestamp + 1;
    }

    msgpack_unpacked_destroy(&result);
    flb_free(data_buf->buffer);

    data_buf->buffer = mp_sbuf.data;
    data_buf->size = mp_sbuf.size;
}

static void test_window()
{
    int i;
    int t;
    int checks;
    int ret;
    char datafile[PATH_MAX];
    struct sp_buffer data_buf;
    struct sp_buffer out_buf;
    struct task_check *check;
    struct flb_config *config;
    struct flb_sp *sp;
    struct flb_sp_task *task;
#ifdef _WIN32
    WSADATA wsa_data;
#endif

    flb_init_env();

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
        TEST_CHECK(task != NULL);

        out_buf.buffer = NULL;
        out_buf.size = 0;

        double record_timestamp = 1.0;
        if (check->window_type == FLB_SP_WINDOW_TUMBLING) {
            ret = file_to_buf(DATA_SAMPLES, &data_buf);
            if (ret == -1) {
                flb_error("[sp test] cannot open DATA_SAMPLES file %s", DATA_SAMPLES);
                flb_free(config);
                return;
            }

            set_record_timestamps(&data_buf, &record_timestamp);

            /* We ingest the buffer every second */
            for (t = 0; t < check->window_size_sec; t++) {
                if (out_buf.buffer != NULL) {
                    flb_free(out_buf.buffer);

                    out_buf.buffer = NULL;
                    out_buf.size = 0;
                }

                ret = flb_sp_do_test(sp, task,
                                     "samples", strlen("samples"),
                                     &data_buf, &out_buf);
                if (ret == -1) {
                    flb_error("[sp test] error processing check '%s'",
                              check->name);
                    flb_sp_task_destroy(task);
                    return;
                }

                /* Sleep for 0.8 seconds, give some delta to the engine */
                usleep(800000);
            }

            if (out_buf.buffer != NULL) {
                flb_free(out_buf.buffer);

                out_buf.buffer = NULL;
                out_buf.size = 0;
            }

            flb_sp_fd_event_test(task->window.fd, task, &out_buf);

            flb_info("[sp test] id=%i, SQL => '%s'", check->id, check->exec);
            check->cb_check(check->id, check, out_buf.buffer, out_buf.size);
            flb_pack_print(out_buf.buffer, out_buf.size);
            flb_free(out_buf.buffer);
        }
        else if (check->window_type == FLB_SP_WINDOW_HOPPING) {
            /* Ingest the buffer every second */
            task->window.fd = 0;
            task->window.fd_hop = 1;
            double record_timestamp = 1.0;
            for (t = 0; t < check->window_size_sec + check->window_hop_sec; t++) {
                ret = snprintf(datafile, sizeof(datafile)-1, "%s%d.mp",
                        DATA_SAMPLES_HOPPING_WINDOW_PATH, t + 1);
                if (!TEST_CHECK(ret <= sizeof(datafile)-1)) {
                    exit(1);
                }
                ret = file_to_buf(datafile, &data_buf);
                if (ret == -1) {
                    flb_error("[sp test] cannot open DATA_SAMPLES file %s", datafile);
                    flb_free(config);
                    return;
                }

                /* Replace record timestamps with test timestamps */
                set_record_timestamps(&data_buf, &record_timestamp);

                ret = flb_sp_do_test(sp, task,
                                     "samples", strlen("samples"),
                                     &data_buf, &out_buf);
                if (ret == -1) {
                    flb_error("[sp test] error processing check '%s'",
                              check->name);
                    flb_sp_task_destroy(task);
                    return;
                }

                /* Sleep for 0.8 seconds, give some delta to the engine */
                usleep(800000);

                /* Hopping event */
                if ((t + 1) % check->window_hop_sec == 0) {
                    if (out_buf.buffer != NULL) {
                        flb_free(out_buf.buffer);

                        out_buf.buffer = NULL;
                        out_buf.size = 0;
                    }

                    flb_sp_fd_event_test(task->window.fd_hop, task, &out_buf);
                }

                /* Window event */
                if ((t + 1) % check->window_size_sec == 0 ||
                    (t + 1 > check->window_size_sec && (t + 1 - check->window_size_sec) % check->window_hop_sec == 0)) {
                    if (out_buf.buffer != NULL) {
                        flb_free(out_buf.buffer);

                        out_buf.buffer = NULL;
                        out_buf.size = 0;
                    }

                    flb_sp_fd_event_test(task->window.fd, task, &out_buf);
                }
                flb_free(data_buf.buffer);
                data_buf.buffer = NULL;
            }

            flb_info("[sp test] id=%i, SQL => '%s'", check->id, check->exec);
            check->cb_check(check->id, check, out_buf.buffer, out_buf.size);
            flb_pack_print(out_buf.buffer, out_buf.size);
            flb_free(out_buf.buffer);
        }

        flb_free(data_buf.buffer);
    }

    flb_sp_destroy(sp);
    mk_event_loop_destroy(config->evl);
    flb_free(config);
#ifdef _WIN32
    WSACleanup();
#endif
}

static void test_snapshot()
{
    int i;
    int t;
    int checks;
    int ret;
    char datafile[PATH_MAX];
    char stream_name[100];
    char window_val[3];
    struct sp_buffer data_buf;
    struct sp_buffer out_buf;
    struct task_check *check;
    struct task_check *check_flush;
    struct flb_config *config;
    struct flb_sp *sp;
    struct flb_sp_task *task;
    struct flb_sp_task *task_flush;

#ifdef _WIN32
    WSADATA wsa_data;
#endif

    flb_init_env();

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

    ret = file_to_buf(DATA_SAMPLES, &data_buf);
    if (ret == -1) {
        flb_error("[sp test] cannot open DATA_SAMPLES file %s", DATA_SAMPLES);
        flb_free(config);
        return;
    }

    /* Total number of checks for select_keys */
    checks = (sizeof(snapshot_checks) / (sizeof(struct task_check) * 2));

    /* Run every test */
    for (i = 0; i < checks; i++) {
        /* Snapshot Create */
        check = (struct task_check *) &snapshot_checks[i][0];

        task = flb_sp_task_create(sp, check->name, check->exec);
        if (!task) {
            flb_error("[sp test] wrong check '%s', fix it!", check->name);
            continue;
        }

        snprintf(stream_name, 100, "%s-%d", "SNAPSHOT", i);
        task->cmd->stream_name = flb_sds_create(stream_name);
        task->cmd->type = FLB_SP_CREATE_SNAPSHOT;
        if (check->window_size_sec > 0) {
            snprintf(window_val, 3, "%d", check->window_size_sec);
            flb_sp_cmd_stream_prop_add(task->cmd, "seconds", window_val);
        }

        if (flb_sp_snapshot_create(task) == -1) {
            flb_error("[sp test] error initializing snapshot for check '%s'!", check->name);
            continue;
        }

        out_buf.buffer = NULL;
        out_buf.size = 0;

        /* Read 1.mp -> 5.mp message pack buffers created for window tests */
        for (t = 0; t < 5; t++) {

            ret = snprintf(datafile, sizeof(datafile)-1, "%s%d.mp",
                    DATA_SAMPLES_HOPPING_WINDOW_PATH, t + 1);
            if (!TEST_CHECK(ret <= sizeof(datafile)-1)) {
                exit(1);
            }

            if (data_buf.buffer) {
                flb_free(data_buf.buffer);
                data_buf.buffer = NULL;
            }

            ret = file_to_buf(datafile, &data_buf);
            if (ret == -1) {
                flb_error("[sp test] cannot open DATA_SAMPLES file %s", datafile);
                flb_free(config);
                return;
            }

            ret = flb_sp_do_test(sp, task,
                                 "samples", strlen("samples"),
                                 &data_buf, &out_buf);

            if (ret == -1) {
                flb_error("[sp test] error processing check '%s'", check->name);
                flb_sp_task_destroy(task);
                continue;
            }
        }

        flb_sp_fd_event_test(task->window.fd, task, &out_buf);

        flb_info("[sp test] id=%i, SQL => '%s'", check->id, check->exec);
        check->cb_check(check->id, check, out_buf.buffer, out_buf.size);
        flb_pack_print(out_buf.buffer, out_buf.size);
        flb_free(out_buf.buffer);

        /* Snapshot flush */
        check_flush = (struct task_check *) &snapshot_checks[i][1];

        task_flush = flb_sp_task_create(sp, check_flush->name, check_flush->exec);
        if (!task_flush) {
            flb_error("[sp test] wrong check '%s', fix it!", check_flush->name);
            continue;
        }

        snprintf(stream_name, 100, "%s-%d", "__flush_SNAPSHOT", i);
        task_flush->cmd->stream_name = flb_sds_create(stream_name);
        task_flush->cmd->type = FLB_SP_FLUSH_SNAPSHOT;

        out_buf.buffer = NULL;
        out_buf.size = 0;

        ret = flb_sp_do_test(sp, task_flush,
                             "samples", strlen("samples"),
                             &data_buf, &out_buf);
        if (ret == -1) {
            flb_error("[sp test] error processing check '%s'", check_flush->name);
            flb_sp_task_destroy(task_flush);
            continue;
        }

        flb_sp_fd_event_test(task->window.fd, task_flush, &out_buf);

        flb_info("[sp test] id=%i, SQL => '%s'", check_flush->id, check_flush->exec);
        check_flush->cb_check(check_flush->id, check_flush, out_buf.buffer, out_buf.size);
        flb_pack_print(out_buf.buffer, out_buf.size);
        flb_free(out_buf.buffer);

        flb_free(data_buf.buffer);
        data_buf.buffer = NULL;
    }

    flb_free(data_buf.buffer);
    flb_sp_destroy(sp);
    mk_event_loop_destroy(config->evl);
    flb_free(config);
#ifdef _WIN32
    WSACleanup();
#endif
}

static void test_conv_from_str_to_num()
{
    struct flb_config *config = NULL;
    struct flb_sp *sp = NULL;
    struct flb_sp_task *task = NULL;
    struct sp_buffer out_buf;
    struct sp_buffer data_buf;
    msgpack_sbuffer sbuf;
    msgpack_packer pck;
    msgpack_unpacked result;
    size_t off = 0;
    char json[4096] = {0};
    int ret;

#ifdef _WIN32
    WSADATA wsa_data;

    WSAStartup(0x0201, &wsa_data);
#endif
    out_buf.buffer = NULL;

    flb_init_env();

    config = flb_config_init();
    config->evl = mk_event_loop_create(256);
    flb_engine_evl_init();
    flb_engine_evl_set(config->evl);

    ret = flb_storage_create(config);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_storage_create failed");
        flb_config_exit(config);
        return;
    }

    sp = flb_sp_create(config);
    if (!TEST_CHECK(sp != NULL)) {
        TEST_MSG("[sp test] cannot create stream processor context");
        goto test_conv_from_str_to_num_end;
    }

    task = flb_sp_task_create(sp, "tail.0", "CREATE STREAM test WITH (tag=\'test\') AS SELECT word, num, COUNT(*) FROM STREAM:tail.0 WINDOW TUMBLING (1 SECOND) GROUP BY word, num;");
    if (!TEST_CHECK(task != NULL)) {
        TEST_MSG("[sp test] wrong check 'conv', fix it!");
        goto test_conv_from_str_to_num_end;
    }

    /* Create input data */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&pck, 2);
    flb_pack_time_now(&pck);
    msgpack_pack_map(&pck, 2);

    msgpack_pack_str(&pck, 4);
    msgpack_pack_str_body(&pck, "word", 4);
    msgpack_pack_str(&pck, 4);
    msgpack_pack_str_body(&pck, "hoge", 4);

    msgpack_pack_str(&pck, 3);
    msgpack_pack_str_body(&pck, "num", 3);
    msgpack_pack_str(&pck, 6);
    msgpack_pack_str_body(&pck, "123456", 6);

    data_buf.buffer = sbuf.data;
    data_buf.size = sbuf.size;

    out_buf.buffer = NULL;
    out_buf.size = 0;

    /* Exec stream processor */
    ret = flb_sp_do_test(sp, task, "tail.0", strlen("tail.0"), &data_buf, &out_buf);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_sp_do_test failed");
        msgpack_sbuffer_destroy(&sbuf);
        goto test_conv_from_str_to_num_end;
    }

    if (!TEST_CHECK(out_buf.size > 0)) {
        TEST_MSG("out_buf size is 0");
        msgpack_sbuffer_destroy(&sbuf);
        goto test_conv_from_str_to_num_end;
    }


    /* Check output buffer. It should contain a number 123456 not a string "123456" */

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, out_buf.buffer, out_buf.size, &off);
    if (!TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS)) {
        TEST_MSG("failed to unpack ret=%d", ret);
        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&sbuf);
        goto test_conv_from_str_to_num_end;
    }

    ret = flb_msgpack_to_json(&json[0], sizeof(json), &result.data);
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("flb_msgpack_to_json failed");
        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&sbuf);
        goto test_conv_from_str_to_num_end;
    }

    if (!TEST_CHECK(strstr(json,"123456") != NULL)) {
        TEST_MSG("number not found");
        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&sbuf);
        goto test_conv_from_str_to_num_end;
    }
    if (!TEST_CHECK(strstr(json,"\"123456\"") == NULL)) {
        TEST_MSG("output should be number type");
        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&sbuf);
        goto test_conv_from_str_to_num_end;
    }

    msgpack_unpacked_destroy(&result);
    msgpack_sbuffer_destroy(&sbuf);

 test_conv_from_str_to_num_end:
    if (out_buf.buffer != NULL) {
        flb_free(out_buf.buffer);
    }

#ifdef _WIN32
    WSACleanup();
#endif
    if (sp != NULL) {
        flb_sp_destroy(sp);
    }
    flb_storage_destroy(config);
    flb_config_exit(config);
}

TEST_LIST = {
    { "invalid_queries", invalid_queries},
    { "select_keys",     test_select_keys},
    { "select_subkeys",  test_select_subkeys},
    { "window",          test_window},
    { "snapshot",        test_snapshot},
    { "conv_from_str_to_num", test_conv_from_str_to_num},
    { NULL }
};
