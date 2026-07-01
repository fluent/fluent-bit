/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_sds.h>
#include "flb_tests_runtime.h"
#include <sys/stat.h>
#include <sys/types.h>

/* Test data */
#include "data/common/json_invalid.h" /* JSON_INVALID */
#include "data/common/json_long.h"    /* JSON_LONG    */
#include "data/common/json_small.h"   /* JSON_SMALL   */

/* Test functions */
void flb_test_file_json_invalid(void);
void flb_test_file_json_long(void);
void flb_test_file_json_small(void);
void flb_test_file_format_csv(void);
void flb_test_file_format_ltsv(void);
void flb_test_file_format_invalid(void);
void flb_test_file_format_out_file(void);
void flb_test_file_path_file(void);
void flb_test_file_path(void);
void flb_test_file_delim_csv(void);
void flb_test_file_delim_ltsv(void);
void flb_test_file_label_delim(void);
void flb_test_file_template(void);
void flb_test_file_mkdir(void);
void flb_test_file_dynamic_path_file(void);
void flb_test_file_dynamic_requires_fallback(void);
void flb_test_file_dynamic_missing_fallback(void);
void flb_test_file_dynamic_unsafe_fallback(void);
void flb_test_file_dynamic_windows_unsafe_fallback(void);
void flb_test_file_dynamic_path_traversal_fallback(void);
void flb_test_file_dynamic_limit_fallback(void);

/* Test list */
TEST_LIST = {
    {"path",            flb_test_file_path},
    {"path_file",       flb_test_file_path_file},
    {"mkdir",           flb_test_file_mkdir},
    {"dynamic_path_file", flb_test_file_dynamic_path_file},
    {"dynamic_requires_fallback", flb_test_file_dynamic_requires_fallback},
    {"dynamic_missing_fallback", flb_test_file_dynamic_missing_fallback},
    {"dynamic_unsafe_fallback", flb_test_file_dynamic_unsafe_fallback},
    {"dynamic_windows_unsafe_fallback", flb_test_file_dynamic_windows_unsafe_fallback},
    {"dynamic_path_traversal_fallback", flb_test_file_dynamic_path_traversal_fallback},
    {"dynamic_limit_fallback", flb_test_file_dynamic_limit_fallback},
    {"template",        flb_test_file_template},
    {"delimiter_ltsv",  flb_test_file_delim_ltsv},
    {"delimiter_csv",   flb_test_file_delim_csv},
    {"label_delimiter", flb_test_file_label_delim},
    {"json_invalid",    flb_test_file_json_invalid   },
    {"json_long",       flb_test_file_json_long      },
    {"json_small",      flb_test_file_json_small     },
    {"format_csv",      flb_test_file_format_csv     },
    {"format_ltsv",     flb_test_file_format_ltsv    },
    {"format_invalid",  flb_test_file_format_invalid },
    {"format_out_file", flb_test_file_format_out_file},

    {NULL, NULL}
};


#define TEST_LOGFILE "flb_test_file_dummy.log"
#define TEST_LOGPATH "out_file"
#define TEST_TIMEOUT 5

void flb_test_file_json_invalid(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_INVALID;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_INVALID) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp == NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

/* It writes a very long JSON map (> 100KB) byte by byte */
void flb_test_file_json_long(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_LONG;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_LONG) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    ret = wait_for_file(TEST_LOGFILE, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

void flb_test_file_json_small(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    ret = wait_for_file(TEST_LOGFILE, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

void flb_test_file_format_csv(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "format", "csv", NULL);
    flb_output_set(ctx, out_ffd, "delimiter", "comma", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    ret = wait_for_file(TEST_LOGFILE, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

void flb_test_file_format_ltsv(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "format", "ltsv", NULL);
    flb_output_set(ctx, out_ffd, "delimiter", "tab", NULL);
    flb_output_set(ctx, out_ffd, "label_delimiter", "comma", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    ret = wait_for_file(TEST_LOGFILE, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

/* https://github.com/fluent/fluent-bit/issues/4152 */
void flb_test_file_format_out_file(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "format", "out_file", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    ret = wait_for_file(TEST_LOGFILE, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

void flb_test_file_format_invalid(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "off", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "format", "xxx", NULL);
    flb_output_set(ctx, out_ffd, "delimiter", "yyy", NULL);
    flb_output_set(ctx, out_ffd, "label_delimiter", "zzz", NULL);

    ret = flb_start(ctx);
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("invalid format should be error");

        flb_stop(ctx);
        flb_destroy(ctx);
        fp = fopen(TEST_LOGFILE, "r");
        TEST_CHECK(fp != NULL);
        if (fp != NULL) {
            fclose(fp);
            remove(TEST_LOGFILE);
        }
    }
    else {
        flb_destroy(ctx);
    }
}

void flb_test_file_path(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_LONG;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;
    flb_sds_t path;
    flb_sds_t file;

    file = flb_sds_create("test");
    if (!TEST_CHECK(file != NULL)) {
        TEST_MSG("flb_sds_create failed");
        return;
    }

    path = flb_sds_create_size(256);
    if (!TEST_CHECK(path != NULL)) {
        TEST_MSG("flb_sds_create_size failed");
        flb_sds_destroy(file);
        return;
    }
    flb_sds_printf(&path, "%s/%s", TEST_LOGPATH, file);

    remove(path);
    remove(TEST_LOGPATH);
    ret = mkdir(TEST_LOGPATH, S_IRUSR | S_IWUSR | S_IXUSR);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("mkdir failed:path=%s errno=%d",TEST_LOGPATH, errno);
        flb_sds_destroy(path);
        flb_sds_destroy(file);
        return;
    }

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", file, NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "path", TEST_LOGPATH, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_LONG) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    ret = wait_for_file(path, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(path, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(path);
    }
    flb_sds_destroy(path);
    flb_sds_destroy(file);
    remove(TEST_LOGPATH);
}

void flb_test_file_path_file(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_LONG;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;
    flb_sds_t path;

    path = flb_sds_create_size(256);
    if (!TEST_CHECK(path != NULL)) {
        TEST_MSG("flb_sds_create_size failed");
        return;
    }
    flb_sds_printf(&path, "%s/%s", TEST_LOGPATH, TEST_LOGFILE);

    remove(path);
    remove(TEST_LOGPATH);
    ret = mkdir(TEST_LOGPATH, S_IRUSR | S_IWUSR | S_IXUSR);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("mkdir failed:path=%s errno=%d",TEST_LOGPATH, errno);
        flb_sds_destroy(path);
        return;
    }

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "path", TEST_LOGPATH, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_LONG) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    ret = wait_for_file(path, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(path, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(path);
    }
    flb_sds_destroy(path);
    remove(TEST_LOGPATH);
}

#define JSON_BASIC "[1448403340,{\"key1\":\"val1\", \"key2\":\"val2\"}]"
#define JSON_DYNAMIC \
    "[1448403340,{\"proxy_name\":\"proxy1\", \"hostname\":\"host1\"}]" \
    "[1448403341,{\"proxy_name\":\"proxy2\", \"hostname\":\"host2\"}]"
#define JSON_DYNAMIC_MISSING "[1448403340,{\"proxy_name\":\"proxy1\"}]"
#define JSON_DYNAMIC_UNSAFE "[1448403340,{\"hostname\":\"../escape.log\"}]"
#define JSON_DYNAMIC_WINDOWS_UNSAFE "[1448403340,{\"hostname\":\"host:one.log\"}]"
#define JSON_DYNAMIC_PATH_TRAVERSAL "[1448403340,{\"proxy_name\":\"..\"}]"
#define JSON_DYNAMIC_LIMIT \
    "[1448403340,{\"hostname\":\"host1\"}]" \
    "[1448403341,{\"hostname\":\"host2\"}]"

void flb_test_file_dynamic_path_file(void)
{
    int ret;
    int bytes;
    char *p = JSON_DYNAMIC;
    char path1[256];
    char path2[256];
    char dir1[256];
    char dir2[256];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    snprintf(dir1, sizeof(dir1), "%s/proxy1", TEST_LOGPATH);
    snprintf(dir2, sizeof(dir2), "%s/proxy2", TEST_LOGPATH);
    snprintf(path1, sizeof(path1), "%s/host1.log", dir1);
    snprintf(path2, sizeof(path2), "%s/host2.log", dir2);
    remove(path1);
    remove(path2);
    rmdir(dir1);
    rmdir(dir2);
    rmdir(TEST_LOGPATH);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1",
                    "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "path", TEST_LOGPATH "/$proxy_name", NULL);
    flb_output_set(ctx, out_ffd, "file", "$hostname.log", NULL);
    flb_output_set(ctx, out_ffd, "fallback_path", TEST_LOGPATH, NULL);
    flb_output_set(ctx, out_ffd, "fallback_file", "metrics.log", NULL);
    flb_output_set(ctx, out_ffd, "mkdir", "true", NULL);
    flb_output_set(ctx, out_ffd, "format", "plain", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    ret = wait_for_file(path1, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);
    ret = wait_for_file(path2, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    remove(path1);
    remove(path2);
    rmdir(dir1);
    rmdir(dir2);
    rmdir(TEST_LOGPATH);
}

void flb_test_file_dynamic_requires_fallback(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "off", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "path", TEST_LOGPATH, NULL);
    flb_output_set(ctx, out_ffd, "file", "$hostname.log", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    if (ret == 0) {
        flb_stop(ctx);
    }
    flb_destroy(ctx);
}

void flb_test_file_dynamic_missing_fallback(void)
{
    int ret;
    int bytes;
    char *p = JSON_DYNAMIC_MISSING;
    char fallback[256];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    snprintf(fallback, sizeof(fallback), "%s/fallback.log", TEST_LOGPATH);
    remove(fallback);
    rmdir(TEST_LOGPATH);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "path", TEST_LOGPATH, NULL);
    flb_output_set(ctx, out_ffd, "file", "$hostname.log", NULL);
    flb_output_set(ctx, out_ffd, "on_missing_field", "fallback", NULL);
    flb_output_set(ctx, out_ffd, "fallback_path", TEST_LOGPATH, NULL);
    flb_output_set(ctx, out_ffd, "fallback_file", "fallback.log", NULL);
    flb_output_set(ctx, out_ffd, "mkdir", "true", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));
    ret = wait_for_file(fallback, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    remove(fallback);
    rmdir(TEST_LOGPATH);
}

void flb_test_file_dynamic_unsafe_fallback(void)
{
    int ret;
    int bytes;
    char *p = JSON_DYNAMIC_UNSAFE;
    char fallback[256];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    snprintf(fallback, sizeof(fallback), "%s/fallback.log", TEST_LOGPATH);
    remove(fallback);
    remove("escape.log");
    rmdir(TEST_LOGPATH);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "path", TEST_LOGPATH, NULL);
    flb_output_set(ctx, out_ffd, "file", "$hostname", NULL);
    flb_output_set(ctx, out_ffd, "on_missing_field", "fallback", NULL);
    flb_output_set(ctx, out_ffd, "fallback_path", TEST_LOGPATH, NULL);
    flb_output_set(ctx, out_ffd, "fallback_file", "fallback.log", NULL);
    flb_output_set(ctx, out_ffd, "mkdir", "true", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));
    ret = wait_for_file(fallback, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(access("escape.log", F_OK) != 0);
    remove(fallback);
    rmdir(TEST_LOGPATH);
}

void flb_test_file_dynamic_windows_unsafe_fallback(void)
{
    int ret;
    int bytes;
    char *p = JSON_DYNAMIC_WINDOWS_UNSAFE;
    char fallback[256];
    char unsafe[256];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    snprintf(fallback, sizeof(fallback), "%s/fallback.log", TEST_LOGPATH);
    snprintf(unsafe, sizeof(unsafe), "%s/host:one.log", TEST_LOGPATH);
    remove(fallback);
    remove(unsafe);
    rmdir(TEST_LOGPATH);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "path", TEST_LOGPATH, NULL);
    flb_output_set(ctx, out_ffd, "file", "$hostname", NULL);
    flb_output_set(ctx, out_ffd, "on_missing_field", "fallback", NULL);
    flb_output_set(ctx, out_ffd, "fallback_path", TEST_LOGPATH, NULL);
    flb_output_set(ctx, out_ffd, "fallback_file", "fallback.log", NULL);
    flb_output_set(ctx, out_ffd, "mkdir", "true", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));
    ret = wait_for_file(fallback, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(access(unsafe, F_OK) != 0);
    remove(fallback);
    remove(unsafe);
    rmdir(TEST_LOGPATH);
}

void flb_test_file_dynamic_limit_fallback(void)
{
    int ret;
    int bytes;
    char *p = JSON_DYNAMIC_LIMIT;
    char first[256];
    char overflow[256];
    char second[256];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    snprintf(first, sizeof(first), "%s/host1.log", TEST_LOGPATH);
    snprintf(second, sizeof(second), "%s/host2.log", TEST_LOGPATH);
    snprintf(overflow, sizeof(overflow), "%s/overflow.log", TEST_LOGPATH);
    remove(first);
    remove(second);
    remove(overflow);
    rmdir(TEST_LOGPATH);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "path", TEST_LOGPATH, NULL);
    flb_output_set(ctx, out_ffd, "file", "$hostname.log", NULL);
    flb_output_set(ctx, out_ffd, "max_dynamic_files", "1", NULL);
    flb_output_set(ctx, out_ffd, "on_limit_reached", "fallback", NULL);
    flb_output_set(ctx, out_ffd, "fallback_path", TEST_LOGPATH, NULL);
    flb_output_set(ctx, out_ffd, "fallback_file", "overflow.log", NULL);
    flb_output_set(ctx, out_ffd, "mkdir", "true", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));
    ret = wait_for_file(first, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);
    ret = wait_for_file(overflow, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(access(second, F_OK) != 0);
    remove(first);
    remove(second);
    remove(overflow);
    rmdir(TEST_LOGPATH);
}

void flb_test_file_dynamic_path_traversal_fallback(void)
{
    int ret;
    int bytes;
    char *p = JSON_DYNAMIC_PATH_TRAVERSAL;
    char fallback[256];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    snprintf(fallback, sizeof(fallback), "%s/fallback.log", TEST_LOGPATH);
    remove(fallback);
    remove("unsafe.log");
    rmdir(TEST_LOGPATH);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "path", TEST_LOGPATH "/$proxy_name", NULL);
    flb_output_set(ctx, out_ffd, "file", "unsafe.log", NULL);
    flb_output_set(ctx, out_ffd, "on_missing_field", "fallback", NULL);
    flb_output_set(ctx, out_ffd, "fallback_path", TEST_LOGPATH, NULL);
    flb_output_set(ctx, out_ffd, "fallback_file", "fallback.log", NULL);
    flb_output_set(ctx, out_ffd, "mkdir", "true", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));
    ret = wait_for_file(fallback, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(access("unsafe.log", F_OK) != 0);
    remove(fallback);
    rmdir(TEST_LOGPATH);
}

void flb_test_file_delim_csv(void)
{
    int ret;
    int bytes;
    char *p = JSON_BASIC;
    char output[256] = {0};
    char *expect = "1448403340.000000000 \"val1\" \"val2\"";
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "format", "csv", NULL);
    flb_output_set(ctx, out_ffd, "delimiter", "space", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    ret = wait_for_file(TEST_LOGFILE, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        bytes = fread(&output[0], sizeof(output), 1, fp);
        if(!TEST_CHECK(bytes > 0 || feof(fp))) {
            TEST_MSG("fread error bytes=%d", bytes);
        }
        if (!TEST_CHECK(strncmp(expect, &output[0], strlen(expect)) == 0)) {
            TEST_MSG("format error\n");
            TEST_MSG("expect: %s\n", expect);
            TEST_MSG("got   : %s",output);
        }

        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

void flb_test_file_delim_ltsv(void)
{
    int ret;
    int bytes;
    char *p = JSON_BASIC;
    char output[256] = {0};
    char *expect = "\"time\":1448403340.000000 \"key1\":\"val1\" \"key2\":\"val2\"";
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "format", "ltsv", NULL);
    flb_output_set(ctx, out_ffd, "delimiter", "space", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    ret = wait_for_file(TEST_LOGFILE, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        bytes = fread(&output[0], sizeof(output), 1, fp);
        if(!TEST_CHECK(bytes > 0 || feof(fp))) {
            TEST_MSG("fread error bytes=%d", bytes);
        }
        if (!TEST_CHECK(strncmp(expect, &output[0], strlen(expect)) == 0)) {
            TEST_MSG("format error\n");
            TEST_MSG("expect: %s\n", expect);
            TEST_MSG("got   : %s",output);
        }

        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

void flb_test_file_label_delim(void)
{
    int ret;
    int bytes;
    char *p = JSON_BASIC;
    char output[256] = {0};
    char *expect = "\"time\" 1448403340.000000 \"key1\" \"val1\" \"key2\" \"val2\"";
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "format", "ltsv", NULL);
    flb_output_set(ctx, out_ffd, "delimiter", "space", NULL);
    flb_output_set(ctx, out_ffd, "label_delimiter", "space", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    ret = wait_for_file(TEST_LOGFILE, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        bytes = fread(&output[0], sizeof(output), 1, fp);
        if(!TEST_CHECK(bytes > 0 || feof(fp))) {
            TEST_MSG("fread error bytes=%d", bytes);
        }
        if (!TEST_CHECK(strncmp(expect, &output[0], strlen(expect)) == 0)) {
            TEST_MSG("format error\n");
            TEST_MSG("expect: %s\n", expect);
            TEST_MSG("got   : %s",output);
        }

        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

void flb_test_file_template(void)
{
    int ret;
    int bytes;
    char *p = JSON_BASIC;
    char output[256] = {0};
    char *expect = "1448403340.000000 KEY1=val1 KEY2=val2";
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "file", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "format", "template", NULL);
    flb_output_set(ctx, out_ffd, "template", "{time} KEY1={key1} KEY2={key2}", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    ret = wait_for_file(TEST_LOGFILE, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        bytes = fread(&output[0], sizeof(output), 1, fp);
        if(!TEST_CHECK(bytes > 0 || feof(fp))) {
            TEST_MSG("fread error bytes=%d", bytes);
        }
        if (!TEST_CHECK(strncmp(expect, &output[0], strlen(expect)) == 0)) {
            TEST_MSG("format error\n");
            TEST_MSG("expect: %s\n", expect);
            TEST_MSG("got   : %s",output);
        }

        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

void flb_test_file_mkdir(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_LONG;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;
    flb_sds_t path;
    flb_sds_t file;

    file = flb_sds_create("test");
    if (!TEST_CHECK(file != NULL)) {
        TEST_MSG("flb_sds_create failed");
        return;
    }

    path = flb_sds_create_size(256);
    if (!TEST_CHECK(path != NULL)) {
        TEST_MSG("flb_sds_create_size failed");
        flb_sds_destroy(file);
        return;
    }
    flb_sds_printf(&path, "%s/%s", TEST_LOGPATH, file);

    remove(path);
    remove(TEST_LOGPATH);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", file, NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "path", TEST_LOGPATH, NULL);
    flb_output_set(ctx, out_ffd, "mkdir", "true", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_LONG) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    ret = wait_for_file(path, 1, TEST_TIMEOUT);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(path, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(path);
    }
    flb_sds_destroy(path);
    flb_sds_destroy(file);
    remove(TEST_LOGPATH);
}
