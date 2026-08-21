/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_utils.h>
#include <chunkio/cio_utils.h>
#include "flb_tests_runtime.h"
#include "../../plugins/out_azure_kusto/azure_kusto_ingest.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <process.h>
#include <windows.h>
#define FLB_KUSTO_GETPID _getpid
#define FLB_KUSTO_BUFFER_DIR_FORMAT "flb-kusto-test-%d"
#else
#include <dirent.h>
#include <unistd.h>
#define FLB_KUSTO_GETPID getpid
#define FLB_KUSTO_BUFFER_DIR_FORMAT "/tmp/flb-kusto-test-%d"
#endif

/* Test data */
#include "data/common/json_invalid.h" /* JSON_INVALID */

static int flb_kusto_rm_rf(const char *path)
{
    int ret;
    struct stat st;

    if (stat(path, &st) != 0) {
        return 0;
    }

    ret = cio_utils_recursive_delete(path);
    if (ret != 0) {
        TEST_MSG("failed to clean buffer directory '%s' errno=%d", path, errno);
    }

    return ret;
}

static int flb_kusto_dir_has_entries(const char *path)
{
#ifdef _WIN32
    int ret;
    int has_entries;
    char pattern[MAX_PATH];
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle;

    ret = snprintf(pattern, sizeof(pattern), "%s\\*", path);
    if (ret <= 0 || (size_t) ret >= sizeof(pattern)) {
        return FLB_FALSE;
    }

    find_handle = FindFirstFileA(pattern, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) {
        return FLB_FALSE;
    }

    has_entries = FLB_FALSE;
    do {
        if (strcmp(find_data.cFileName, ".") != 0 &&
            strcmp(find_data.cFileName, "..") != 0) {
            has_entries = FLB_TRUE;
            break;
        }
    } while (FindNextFileA(find_handle, &find_data));

    FindClose(find_handle);
    return has_entries;
#else
    DIR *dir;
    struct dirent *entry;
    int has_entries;

    dir = opendir(path);
    if (!dir) {
        return FLB_FALSE;
    }

    has_entries = FLB_FALSE;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            has_entries = FLB_TRUE;
            break;
        }
    }

    closedir(dir);
    return has_entries;
#endif
}

static void flb_kusto_sleep_seconds(int seconds)
{
#ifdef _WIN32
    Sleep((DWORD) seconds * 1000);
#else
    sleep(seconds);
#endif
}

/* Test functions */
void flb_test_azure_kusto_json_invalid(void);
void flb_test_azure_kusto_managed_identity_system(void);
void flb_test_azure_kusto_managed_identity_user(void);
void flb_test_azure_kusto_service_principal(void);
void flb_test_azure_kusto_workload_identity(void);
void flb_test_azure_kusto_buffer_delete_early_enqueue_result(void);
void flb_test_azure_kusto_buffering_backlog(void);

/* Test list */
TEST_LIST = {
    {"json_invalid", flb_test_azure_kusto_json_invalid},
    {"managed_identity_system", flb_test_azure_kusto_managed_identity_system},
    {"managed_identity_user", flb_test_azure_kusto_managed_identity_user},
    {"service_principal", flb_test_azure_kusto_service_principal},
    {"workload_identity", flb_test_azure_kusto_workload_identity},
    {"buffer_delete_early_enqueue_result",
     flb_test_azure_kusto_buffer_delete_early_enqueue_result},
    {"buffering_backlog", flb_test_azure_kusto_buffering_backlog},
    {NULL, NULL}
};

void flb_test_azure_kusto_json_invalid(void)
{
    int i;
    int ret;
    int total;
    int bytes;
    char *p = (char *) JSON_INVALID;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_kusto", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "managed_identity", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "system", NULL);
    flb_output_set(ctx, out_ffd, "ingestion_endpoint", "https://ingest-CLUSTER.kusto.windows.net", NULL);
    flb_output_set(ctx, out_ffd, "database_name", "telemetrydb", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "logs", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    total = 0;
    for (i = 0; i < (int) sizeof(JSON_INVALID) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
        total++;
    }

    flb_kusto_sleep_seconds(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for system-assigned managed identity */
void flb_test_azure_kusto_managed_identity_system(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_kusto", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "managed_identity", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "system", NULL);
    flb_output_set(ctx, out_ffd, "ingestion_endpoint", "https://ingest-CLUSTER.kusto.windows.net", NULL);
    flb_output_set(ctx, out_ffd, "database_name", "telemetrydb", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "logs", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for user-assigned managed identity */
void flb_test_azure_kusto_managed_identity_user(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_kusto", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "managed_identity", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "00000000-0000-0000-0000-000000000000", NULL);  /* Example UUID */
    flb_output_set(ctx, out_ffd, "ingestion_endpoint", "https://ingest-CLUSTER.kusto.windows.net", NULL);
    flb_output_set(ctx, out_ffd, "database_name", "telemetrydb", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "logs", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for service principal authentication */
void flb_test_azure_kusto_service_principal(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_kusto", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "service_principal", NULL);
    flb_output_set(ctx, out_ffd, "tenant_id", "your-tenant-id", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "your-client-id", NULL);
    flb_output_set(ctx, out_ffd, "client_secret", "your-client-secret", NULL);
    flb_output_set(ctx, out_ffd, "ingestion_endpoint", "https://ingest-CLUSTER.kusto.windows.net", NULL);
    flb_output_set(ctx, out_ffd, "database_name", "telemetrydb", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "logs", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for workload identity authentication */
void flb_test_azure_kusto_workload_identity(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_kusto", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "workload_identity", NULL);
    flb_output_set(ctx, out_ffd, "tenant_id", "your-tenant-id", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "your-client-id", NULL);
    flb_output_set(ctx, out_ffd, "workload_identity_token_file", "/path/to/token/file", NULL);
    flb_output_set(ctx, out_ffd, "ingestion_endpoint", "https://ingest-CLUSTER.kusto.windows.net", NULL);
    flb_output_set(ctx, out_ffd, "database_name", "telemetrydb", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "logs", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_azure_kusto_buffer_delete_early_enqueue_result(void)
{
    struct flb_azure_kusto ctx;
    struct azure_kusto_file upload_file;
    int ret;

    memset(&ctx, 0, sizeof(ctx));
    memset(&upload_file, 0, sizeof(upload_file));

    ctx.buffering_enabled = FLB_TRUE;
    ctx.buffer_file_delete_early = FLB_TRUE;

    ret = azure_kusto_should_early_delete_buffer_file(&ctx, &upload_file, -1);
    TEST_CHECK_(ret == FLB_FALSE,
                "failed enqueue must keep local buffer available for retry");

    ret = azure_kusto_should_early_delete_buffer_file(&ctx, &upload_file, 0);
    TEST_CHECK_(ret == FLB_TRUE,
                "successful enqueue should allow early local buffer deletion");

    ctx.buffer_file_delete_early = FLB_FALSE;
    ret = azure_kusto_should_early_delete_buffer_file(&ctx, &upload_file, 0);
    TEST_CHECK(ret == FLB_FALSE);

    ctx.buffer_file_delete_early = FLB_TRUE;
    ret = azure_kusto_should_early_delete_buffer_file(&ctx, NULL, 0);
    TEST_CHECK(ret == FLB_FALSE);

    ctx.buffering_enabled = FLB_FALSE;
    ret = azure_kusto_should_early_delete_buffer_file(&ctx, &upload_file, 0);
    TEST_CHECK(ret == FLB_FALSE);
}

/* Regression: exercise buffering-enabled backlog processing on restart */
void flb_test_azure_kusto_buffering_backlog(void)
{
    int i;
    int ret;
    int has_buffered_chunks;
    char buffer_dir[64];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ret = snprintf(buffer_dir, sizeof(buffer_dir), FLB_KUSTO_BUFFER_DIR_FORMAT,
                   (int) FLB_KUSTO_GETPID());
    if (ret <= 0 || (size_t) ret >= sizeof(buffer_dir)) {
        TEST_MSG("failed to build buffer directory path");
        TEST_CHECK(ret > 0 && (size_t) ret < sizeof(buffer_dir));
        return;
    }

    ret = flb_kusto_rm_rf(buffer_dir);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }

    ret = flb_utils_mkdir(buffer_dir, 0700);
    if (ret != 0) {
        TEST_MSG("failed to create buffer directory '%s' errno=%d", buffer_dir, errno);
        TEST_CHECK(ret == 0);
        return;
    }

    /* First run: enable buffering and write data to disk */
    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "dummy", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    flb_input_set(ctx, in_ffd, "dummy", "{\"k\":\"v\"}", NULL);
    flb_input_set(ctx, in_ffd, "samples", "1", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_kusto", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "managed_identity", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "system", NULL);
    flb_output_set(ctx, out_ffd, "ingestion_endpoint",
                   "https://ingest-CLUSTER.kusto.windows.net", NULL);
    flb_output_set(ctx, out_ffd, "database_name", "telemetrydb", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "logs", NULL);
    flb_output_set(ctx, out_ffd, "buffering_enabled", "true", NULL);
    flb_output_set(ctx, out_ffd, "buffer_dir", buffer_dir, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 5; i++) {
        if (flb_kusto_dir_has_entries(buffer_dir) == FLB_TRUE) {
            break;
        }
        flb_kusto_sleep_seconds(1);
    }

    flb_stop(ctx);
    flb_destroy(ctx);

    has_buffered_chunks = flb_kusto_dir_has_entries(buffer_dir);
    TEST_CHECK_(has_buffered_chunks == FLB_TRUE,
                "expected buffered chunks in '%s'", buffer_dir);

    /* Second run: restart and flush while backlog is present */
    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "dummy", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    flb_input_set(ctx, in_ffd, "dummy", "{\"k\":\"v2\"}", NULL);
    flb_input_set(ctx, in_ffd, "samples", "1", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_kusto", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "managed_identity", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "system", NULL);
    flb_output_set(ctx, out_ffd, "ingestion_endpoint",
                   "https://ingest-CLUSTER.kusto.windows.net", NULL);
    flb_output_set(ctx, out_ffd, "database_name", "telemetrydb", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "logs", NULL);
    flb_output_set(ctx, out_ffd, "buffering_enabled", "true", NULL);
    flb_output_set(ctx, out_ffd, "buffer_dir", buffer_dir, NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "6s", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_kusto_sleep_seconds(8); /* drive flush, backlog ingest, and upload timer */

    flb_stop(ctx);
    flb_destroy(ctx);

    ret = flb_kusto_rm_rf(buffer_dir);
    TEST_CHECK(ret == 0);
}
