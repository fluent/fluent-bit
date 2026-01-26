/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_time.h>
#include "flb_tests_internal.h"
#include "chunkio/chunkio.h"
#include "data/input_chunk/log/test_buffer_drop_chunks.h"

#define DPATH FLB_TESTS_DATA_PATH "data/input_chunk/"
#define MAX_LINES        32

int64_t result_time;
struct tail_test_result {
    const char *target;
    int   nMatched;
};

struct tail_file_lines {
  char *lines[MAX_LINES];
  int lines_c;
};

static inline int64_t set_result(int64_t v)
{
    int64_t old = __sync_lock_test_and_set(&result_time, v);
    return old;
}

static int file_to_buf(const char *path, char **out_buf, size_t *out_size)
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

/* Given a target, lookup the .out file and return it content in a tail_file_lines structure */
static struct tail_file_lines *get_out_file_content(const char *target)
{
    int i;
    int ret;
    char file[PATH_MAX];
    char *p;
    char *out_buf;
    size_t out_size;
    struct tail_file_lines *file_lines = flb_malloc(sizeof (struct tail_file_lines));
    file_lines->lines_c = 0;

    snprintf(file, sizeof(file) - 1, DPATH "out/%s.out", target);

    ret = file_to_buf(file, &out_buf, &out_size);
    TEST_CHECK_(ret == 0, "getting output file content: %s", file);
    if (ret != 0) {
        file_lines->lines_c = 0;
        return file_lines;
    }

    file_lines->lines[file_lines->lines_c++] = out_buf;

    for (i = 0; i < out_size; i++) {
      // Nullify \n and \r characters
      p = (char *)(out_buf + i);
      if (*p == '\n' || *p == '\r') {
        *p = '\0';

        if (i == out_size - 1) {
          break;
        }

        if (*++p != '\0' && *p != '\n' && *p != '\r' && file_lines->lines_c < MAX_LINES) {
          file_lines->lines[file_lines->lines_c++] = p;
        }
      }
    }

    // printf("Just before return: %s\n", file_lines.lines[0]);
    return file_lines;
}

static int cb_check_result(void *record, size_t size, void *data)
{
    int i;
    struct tail_test_result *result;
    struct tail_file_lines *out;

    result = (struct tail_test_result *) data;

    char *check;

    out = get_out_file_content(result->target);
    // printf("What we got from function: %s\n", out.lines[0]);
    if (!out->lines_c) {
        goto exit;
    }
   /*
    * Our validation is: check that the one of the output lines
    * in the output record.
    */
    for (i = 0; i<out->lines_c; i++) {
      check = strstr(record, out->lines[i]);
      if (check != NULL) {
          result->nMatched++;
          goto exit;
      }
    }

exit:
    if (size > 0) {
        flb_free(record);
    }
    if (out->lines_c) {
        flb_free(out->lines[0]);
        flb_free(out);
    }
    return 0;
}

void do_test(char *system, const char *target, ...)
{
    int64_t ret;
    flb_ctx_t    *ctx    = NULL;
    int in_ffd;
    int out_ffd;
    char path[PATH_MAX];
    struct tail_test_result result = {0};
    char *tmpdir;
    char storage_path[PATH_MAX];

    tmpdir = flb_test_env_tmpdir();
    TEST_CHECK(tmpdir != NULL);
    if (!tmpdir) {
        return;
    }
    snprintf(storage_path, sizeof(storage_path) - 1, "%s/input-chunk-test-%s",
             tmpdir, target);
    flb_free(tmpdir);

    result.nMatched = 0;
    result.target = target;

    struct flb_lib_out_cb cb;
    cb.cb   = cb_check_result;
    cb.data = &result;

    /* initialize */
    set_result(0);

    ctx = flb_create();

    /* create chunks in /tmp folder */
    ret = flb_service_set(ctx,
                          "Parsers_File", DPATH "parser.conf",
                          "storage.path", storage_path,
                          "Log_Level", "error",
                          NULL);
    TEST_CHECK_(ret == 0, "setting service options");

    in_ffd = flb_input(ctx, (char *) system, NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_CHECK(flb_input_set(ctx, in_ffd, "tag", "test", NULL) == 0);

    /* Compose path based on target */
    snprintf(path, sizeof(path) - 1, DPATH "log/%s.log", target);
    TEST_CHECK_(access(path, R_OK) == 0, "accessing log file: %s", path);

    TEST_CHECK(flb_input_set(ctx, in_ffd,
                             "Path", path,
                             "storage.type", "filesystem",
                             "Parser", "docker",
                             NULL) == 0);

    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd,
                              "match", "test",
                              "format", "json",
                              "storage.total_limit_size", "1K",
                              NULL) == 0);

    TEST_CHECK(flb_service_set(ctx, "Flush", "0.5",
                                    "Grace", "1",
                                    NULL) == 0);

    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK_(ret == 0, "starting engine");

    sleep(1);

    ret = flb_stop(ctx);
    TEST_CHECK_(ret == 0, "stopping engine");

    if (ctx) {
        flb_destroy(ctx);
    }
}

void flb_test_input_chunk_exceed_limit()
{
    /*
     * For this test, the input is a log file with more than 1000 bytes.
     * However we set the limit of storage.total_limit_size to be 1K, no
     * data should be flushed to the destination as we don't have enough
     * space to buffer the data.
     */
    do_test("tail", "a_thousand_plus_one_bytes",
            NULL);
}

void flb_test_input_chunk_buffer_valid()
{
    do_test("tail", "test_buffer_valid",
            NULL);
}

void flb_test_input_chunk_dropping_chunks()
{
    int i;
    int ret;
    int in_ffd;
    int out_ffd;
    int size = sizeof(TEST_BUFFER_DROP_CHUNKS) - 1;
    flb_ctx_t *ctx;
    size_t total_bytes;
    struct flb_input_instance *i_ins;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_chunk *ic;
    struct flb_task *task;
    char *storage_path;

    storage_path = flb_test_tmpdir_cat("/input-chunk-test/");
    TEST_CHECK(storage_path != NULL);
    if (!storage_path) {
        return;
    }

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();

    /* create chunks in /tmp folder */
    ret = flb_service_set(ctx,
                          "flush", "2", "grace", "1",
                          "storage.path", storage_path,
                          "Log_Level", "error",
                          NULL);

    TEST_CHECK_(ret == 0, "setting service options");

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(flb_input_set(ctx, in_ffd,
                             "tag", "test",
                             "storage.type", "filesystem",
                             NULL) == 0);

    /* an invalid output destination */
    out_ffd = flb_output(ctx, (char *) "http", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "Host", "127.0.0.1",
                   "Port", "1",
                   "storage.total_limit_size", "1K",
                   NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    i_ins = mk_list_entry_first(&ctx->config->inputs,
                                struct flb_input_instance,
                                _head);

    /* Ingest data sample */
    for (i = 0; i < 10; ++i) {
        flb_lib_push(ctx, in_ffd, (char *) TEST_BUFFER_DROP_CHUNKS, size);
        sleep(1);
        total_bytes = flb_input_chunk_total_size(i_ins);
        ret = total_bytes > 1000 ? -1 : 0;
        TEST_CHECK(ret == 0);
    }

    flb_time_msleep(2100);
    flb_stop(ctx);
    flb_destroy(ctx);
    flb_free(storage_path);
}

static int gen_buf(msgpack_sbuffer *mp_sbuf, char *buf, size_t buf_size)
{
    msgpack_unpacked result;
    msgpack_packer mp_pck;

    msgpack_unpacked_init(&result);

    /* Initialize local msgpack buffer */
    msgpack_packer_init(&mp_pck, mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_str_body(&mp_pck, buf, buf_size);
    msgpack_unpacked_destroy(&result);

    return 0;
}

static int log_cb(struct cio_ctx *data, int level, const char *file, int line,
                  char *str)
{
    if (level == CIO_LOG_ERROR) {
        flb_error("[fstore] %s", str);
    }
    else if (level == CIO_LOG_WARN) {
        flb_warn("[fstore] %s", str);
    }
    else if (level == CIO_LOG_INFO) {
        flb_info("[fstore] %s", str);
    }
    else if (level == CIO_LOG_DEBUG) {
        flb_debug("[fstore] %s", str);
    }

    return 0;
}

/* This tests uses the subsystems of the engine directly
 * to avoid threading issues when submitting chunks.
 */
void flb_test_input_chunk_fs_chunks_size_real()
{
    int records;
    bool have_size_discrepancy = FLB_FALSE;
    bool has_checked_size = FLB_FALSE;
    struct flb_input_instance *i_ins;
    struct flb_output_instance *o_ins;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_chunk *ic;
    struct flb_task *task;
    size_t chunk_size = 0;
    struct flb_config *cfg;
    struct cio_ctx *cio;
    msgpack_sbuffer mp_sbuf;
    char buf[262144];
    struct mk_event_loop *evl;
    struct cio_options opts = {0};
    char *root_path;

    root_path = flb_test_tmpdir_cat("/input-chunk-fs_chunks-size_real");
    TEST_CHECK(root_path != NULL);
    if (!root_path) {
        return;
    }

    flb_init_env();
    cfg = flb_config_init();
    evl = mk_event_loop_create(256);

    TEST_CHECK(evl != NULL);
    cfg->evl = evl;

    flb_log_create(cfg, FLB_LOG_STDERR, FLB_LOG_DEBUG, NULL);

    i_ins = flb_input_new(cfg, "dummy", NULL, FLB_TRUE);
    i_ins->storage_type = CIO_STORE_FS;

    cio_options_init(&opts);

    opts.root_path = root_path;
    opts.log_cb = log_cb;
    opts.log_level = CIO_LOG_DEBUG;
    opts.flags = CIO_OPEN;

    cio = cio_create(&opts);
    flb_storage_input_create(cio, i_ins);
    flb_input_init_all(cfg);

    o_ins = flb_output_new(cfg, "http", NULL, FLB_TRUE);
    // not the right way to do this
    o_ins->id = 1;
    TEST_CHECK_(o_ins != NULL, "unable to instance output");
    flb_output_set_property(o_ins, "match", "*");
    flb_output_set_property(o_ins, "storage.total_limit_size", "1M");

    TEST_CHECK_((flb_router_io_set(cfg) != -1), "unable to router");

    /* fill up the chunk ... */
    memset((void *)buf, 0x41, sizeof(buf));
    msgpack_sbuffer_init(&mp_sbuf);
    gen_buf(&mp_sbuf, buf, sizeof(buf));

    records = flb_mp_count(buf, sizeof(buf));
    flb_input_chunk_append_raw(i_ins, FLB_INPUT_LOGS, records, "dummy", 4, (void *)buf, sizeof(buf));
    msgpack_sbuffer_destroy(&mp_sbuf);

    /* then force a realloc? */
    memset((void *)buf, 0x42, 256);
    msgpack_sbuffer_init(&mp_sbuf);
    gen_buf(&mp_sbuf, buf, 256);
    flb_input_chunk_append_raw(i_ins, FLB_INPUT_LOGS, 256, "dummy", 4, (void *)buf, 256);
    msgpack_sbuffer_destroy(&mp_sbuf);

    /* Check each test chunk for size discrepancy */
    mk_list_foreach_safe(head, tmp, &i_ins->chunks) {
        ic = mk_list_entry(head, struct flb_input_chunk, _head);
        if (cio_chunk_get_real_size(ic->chunk) != cio_chunk_get_content_size(ic->chunk)) {
            have_size_discrepancy = FLB_TRUE;
        }
        chunk_size += flb_input_chunk_get_real_size(ic);
    }

    TEST_CHECK_(have_size_discrepancy == FLB_TRUE, "need a size discrepancy");

    /* check fs_chunks_size for output plugins against logical and
     *  physical size
     */
    mk_list_foreach_safe(head, tmp, &ic->in->config->outputs) {
        o_ins = mk_list_entry(head, struct flb_output_instance, _head);
        flb_info("[input chunk test] chunk_size=%zu fs_chunk_size=%zu", chunk_size,
                 o_ins->fs_chunks_size);
        has_checked_size = FLB_TRUE;
        TEST_CHECK_(chunk_size == o_ins->fs_chunks_size, "fs_chunks_size must match total real size");
    }
    TEST_CHECK_(has_checked_size == FLB_TRUE, "need to check size discrepancy");

    /* FORCE clean up test tasks*/
    mk_list_foreach_safe(head, tmp, &i_ins->tasks) {
        task = mk_list_entry(head, struct flb_task, _head);
        flb_info("[task] cleanup test task");
        flb_task_destroy(task, FLB_TRUE);
    }

    /* clean up test chunks */
    mk_list_foreach_safe(head, tmp, &i_ins->chunks) {
        ic = mk_list_entry(head, struct flb_input_chunk, _head);
        flb_input_chunk_destroy(ic, FLB_TRUE);
    }

    cio_destroy(cio);
    flb_router_exit(cfg);
    flb_input_exit_all(cfg);
    flb_output_exit(cfg);
    flb_config_exit(cfg);
    flb_free(root_path);
}

/* This tests uses the subsystems of the engine directly
 * to avoid threading issues when submitting chunks.
 */
void flb_test_input_chunk_correct_total_records(void)
{
    int records;
    struct flb_input_instance *i_ins;
    struct flb_output_instance *o_ins;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_chunk *ic;
    struct flb_task *task;
    struct flb_config *cfg;
    struct cio_ctx *cio;
    msgpack_sbuffer mp_sbuf;
    char buf[262144];
    struct mk_event_loop *evl;
    struct cio_options opts = {0};
    char *root_path;

    root_path = flb_test_tmpdir_cat("/input-chunk-fs_chunks-size_real");
    TEST_CHECK(root_path != NULL);
    if (!root_path) {
        return;
    }

    flb_init_env();
    cfg = flb_config_init();
    evl = mk_event_loop_create(256);

    TEST_CHECK(evl != NULL);
    cfg->evl = evl;

    flb_log_create(cfg, FLB_LOG_STDERR, FLB_LOG_DEBUG, NULL);

    i_ins = flb_input_new(cfg, "dummy", NULL, FLB_TRUE);
    i_ins->storage_type = CIO_STORE_FS;

    cio_options_init(&opts);

    opts.root_path = root_path;
    opts.log_cb = log_cb;
    opts.log_level = CIO_LOG_DEBUG;
    opts.flags = CIO_OPEN;

    cio = cio_create(&opts);
    flb_storage_input_create(cio, i_ins);
    flb_input_init_all(cfg);

    o_ins = flb_output_new(cfg, "http", NULL, FLB_TRUE);
    // not the right way to do this
    o_ins->id = 1;
    TEST_CHECK_(o_ins != NULL, "unable to instance output");
    flb_output_set_property(o_ins, "match", "*");
    flb_output_set_property(o_ins, "storage.total_limit_size", "1M");

    TEST_CHECK_((flb_router_io_set(cfg) != -1), "unable to router");

    /* fill up the chunk ... */
    memset((void *)buf, 0x41, sizeof(buf));
    msgpack_sbuffer_init(&mp_sbuf);
    gen_buf(&mp_sbuf, buf, sizeof(buf));

    records = flb_mp_count(buf, sizeof(buf));
    flb_input_chunk_append_raw(i_ins, FLB_INPUT_LOGS, records, "dummy", 4, (void *)buf, sizeof(buf));
    msgpack_sbuffer_destroy(&mp_sbuf);

    /* Check each chunk's total records */
    mk_list_foreach_safe(head, tmp, &i_ins->chunks) {
        ic = mk_list_entry(head, struct flb_input_chunk, _head);
        TEST_CHECK_(ic->total_records > 0, "found input chunk with 0 total records");
    }

    /* FORCE clean up test tasks*/
    mk_list_foreach_safe(head, tmp, &i_ins->tasks) {
        task = mk_list_entry(head, struct flb_task, _head);
        flb_info("[task] cleanup test task");
        flb_task_destroy(task, FLB_TRUE);
    }

    /* clean up test chunks */
    mk_list_foreach_safe(head, tmp, &i_ins->chunks) {
        ic = mk_list_entry(head, struct flb_input_chunk, _head);
        flb_input_chunk_destroy(ic, FLB_TRUE);
    }

    cio_destroy(cio);
    flb_router_exit(cfg);
    flb_input_exit_all(cfg);
    flb_output_exit(cfg);
    flb_config_exit(cfg);
    flb_free(root_path);
}


/* Test list */
TEST_LIST = {
    {"input_chunk_exceed_limit",       flb_test_input_chunk_exceed_limit},
    {"input_chunk_buffer_valid",       flb_test_input_chunk_buffer_valid},
    {"input_chunk_dropping_chunks",    flb_test_input_chunk_dropping_chunks},
    {"input_chunk_fs_chunk_size_real", flb_test_input_chunk_fs_chunks_size_real},
    {"input_chunk_correct_total_records", flb_test_input_chunk_correct_total_records},
    {NULL, NULL}
};
