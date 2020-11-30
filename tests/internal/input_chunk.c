/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fluent-bit/flb_input_chunk.h>
#include "flb_tests_internal.h"

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
    
    for (i=0; i<out_size; i++) {
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
    for (i=0; i<out->lines_c; i++) {
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
                          "storage.path", "/tmp/input-chunk-test/",
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

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();

    /* create chunks in /tmp folder */
    ret = flb_service_set(ctx,
                          "flush", "1", "grace", "1",
                          "storage.path", "/tmp/input-chunk-test/",
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

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"input_chunk_exceed_limit",       flb_test_input_chunk_exceed_limit},
    {"input_chunk_buffer_valid",       flb_test_input_chunk_buffer_valid},
    {"input_chunk_dropping_chunks",    flb_test_input_chunk_dropping_chunks},
    {NULL, NULL}
};
