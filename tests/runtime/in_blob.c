/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_time.h>
#ifdef FLB_HAVE_SQLDB
#include <fluent-bit/flb_sqldb.h>
#endif
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "flb_tests_runtime.h"
#include "../include/flb_tests_tmpdir.h"

/*
 * in_blob used to overflow the stack when a recursive glob matched a
 * directory (for example a double-star pattern, or a dotted directory
 * name against a suffix that requires a dot). These tests build that tree
 * and require the scan to finish and register only the matching files.
 */

struct blob_expect {
    const char *relative;
    int present;
};

static int mkdir_parents(const char *file_path)
{
    char dir[PATH_MAX];
    char *cursor;
    int len;
    int ret;

    len = snprintf(dir, sizeof(dir), "%s", file_path);
    if (len <= 0 || (size_t) len >= sizeof(dir)) {
        return -1;
    }

    cursor = strrchr(dir, '/');
    if (cursor == NULL || cursor == dir) {
        return 0;
    }
    *cursor = '\0';

    for (cursor = dir + 1; *cursor != '\0'; cursor++) {
        if (*cursor != '/') {
            continue;
        }

        *cursor = '\0';
        ret = flb_test_mkdir(dir);
        if (ret != 0 && errno != EEXIST) {
            return -1;
        }
        *cursor = '/';
    }

    ret = flb_test_mkdir(dir);
    if (ret != 0 && errno != EEXIST) {
        return -1;
    }

    return 0;
}

static int write_file(const char *root, const char *relative)
{
    char path[PATH_MAX];
    FILE *fp;
    int len;
    int ret;

    len = snprintf(path, sizeof(path), "%s/%s", root, relative);
    if (len <= 0 || (size_t) len >= sizeof(path)) {
        return -1;
    }

    ret = mkdir_parents(path);
    if (ret != 0) {
        return -1;
    }

    fp = fopen(path, "wb");
    if (fp == NULL) {
        return -1;
    }

    ret = fwrite(relative, 1, strlen(relative), fp);
    if (ret != (int) strlen(relative)) {
        fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0) {
        return -1;
    }

    return 0;
}

static void remove_tree_file(const char *root, const char *relative)
{
    char path[PATH_MAX];
    char *cursor;
    int len;

    len = snprintf(path, sizeof(path), "%s/%s", root, relative);
    if (len <= 0 || (size_t) len >= sizeof(path)) {
        return;
    }

    remove(path);

    /* Drop directories created for this relative path, deepest first. */
    cursor = strrchr(path, '/');
    while (cursor != NULL && cursor != path) {
        *cursor = '\0';
        if (strcmp(path, root) == 0) {
            break;
        }
        flb_test_rmdir(path);
        cursor = strrchr(path, '/');
    }
}

#ifdef FLB_HAVE_SQLDB
static int db_has_path(const char *db_path, const char *file_path)
{
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int ret;
    int found;

    db = NULL;
    stmt = NULL;
    found = 0;

    ret = sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL);
    if (ret != SQLITE_OK) {
        if (db != NULL) {
            sqlite3_close(db);
        }
        return 0;
    }

    sqlite3_busy_timeout(db, 200);
    ret = sqlite3_prepare_v2(db,
                             "SELECT COUNT(*) FROM in_blob_files WHERE path = ?;",
                             -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    sqlite3_bind_text(stmt, 1, file_path, -1, SQLITE_STATIC);
    ret = sqlite3_step(stmt);
    if (ret == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 1) {
        found = 1;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return found;
}

static int wait_for_registration(const char *db_path, const char *file_path)
{
    int i;

    for (i = 0; i < 100; i++) {
        if (db_has_path(db_path, file_path) == 1) {
            return 0;
        }
        flb_time_msleep(100);
    }

    return -1;
}

static void test_recursive_glob(const char *suffix,
                                const char *wait_relative,
                                const struct blob_expect *expect,
                                int expect_count)
{
    flb_ctx_t *ctx;
    char *root;
    char pattern[PATH_MAX];
    char db_path[PATH_MAX];
    char file_path[PATH_MAX];
    const char *samples[] = {
        "top.bin",
        "plain",
        "subfolder/c.bin",
        "subfolder/nested/deep.bin",
        "v1.2/notes.txt",
        "v1.2/data.bin"
    };
    int in_ffd;
    int out_ffd;
    int ret;
    int i;
    int len;
    int sample_count;

    sample_count = sizeof(samples) / sizeof(samples[0]);
    root = flb_test_tmpdir_cat("/flb-in-blob-XXXXXX");
    if (!TEST_CHECK(root != NULL)) {
        return;
    }
    if (!TEST_CHECK(mkdtemp(root) != NULL)) {
        flb_free(root);
        return;
    }

    len = snprintf(db_path, sizeof(db_path), "%s.db", root);
    if (!TEST_CHECK(len > 0 && (size_t) len < sizeof(db_path))) {
        flb_test_rmdir(root);
        flb_free(root);
        return;
    }

    len = snprintf(pattern, sizeof(pattern), "%s%s", root, suffix);
    if (!TEST_CHECK(len > 0 && (size_t) len < sizeof(pattern))) {
        flb_test_rmdir(root);
        flb_free(root);
        return;
    }

    for (i = 0; i < sample_count; i++) {
        ret = write_file(root, samples[i]);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("could not create %s/%s", root, samples[i]);
            goto cleanup_files;
        }
    }

    ctx = flb_create();
    if (!TEST_CHECK(ctx != NULL)) {
        goto cleanup_files;
    }

    ret = flb_service_set(ctx,
                          "Flush", "0.2",
                          "Grace", "2",
                          "Log_Level", "error",
                          NULL);
    if (!TEST_CHECK(ret == 0)) {
        flb_destroy(ctx);
        goto cleanup_files;
    }

    in_ffd = flb_input(ctx, (char *) "blob", NULL);
    if (!TEST_CHECK(in_ffd >= 0)) {
        flb_destroy(ctx);
        goto cleanup_files;
    }

    ret = flb_input_set(ctx, in_ffd,
                        "tag", "test",
                        "path", pattern,
                        "database_file", db_path,
                        "scan_refresh_interval", "1s",
                        NULL);
    if (!TEST_CHECK(ret == 0)) {
        flb_destroy(ctx);
        goto cleanup_files;
    }

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    if (!TEST_CHECK(out_ffd >= 0)) {
        flb_destroy(ctx);
        goto cleanup_files;
    }

    ret = flb_output_set(ctx, out_ffd, "match", "test", NULL);
    if (!TEST_CHECK(ret == 0)) {
        flb_destroy(ctx);
        goto cleanup_files;
    }

    ret = flb_start(ctx);
    if (!TEST_CHECK(ret == 0)) {
        flb_destroy(ctx);
        goto cleanup_files;
    }

    len = snprintf(file_path, sizeof(file_path), "%s/%s", root, wait_relative);
    if (!TEST_CHECK(len > 0 && (size_t) len < sizeof(file_path))) {
        flb_stop(ctx);
        flb_destroy(ctx);
        goto cleanup_files;
    }

    ret = wait_for_registration(db_path, file_path);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("timed out waiting for %s", file_path);
    }

    ret = flb_stop(ctx);
    TEST_CHECK(ret == 0);
    flb_destroy(ctx);

    for (i = 0; i < expect_count; i++) {
        len = snprintf(file_path, sizeof(file_path), "%s/%s",
                       root, expect[i].relative);
        if (!TEST_CHECK(len > 0 && (size_t) len < sizeof(file_path))) {
            continue;
        }

        if (expect[i].present == FLB_TRUE) {
            TEST_CHECK_(db_has_path(db_path, file_path) == 1,
                        "missing registered file %s", file_path);
        }
        else {
            TEST_CHECK_(db_has_path(db_path, file_path) == 0,
                        "unexpected registered file %s", file_path);
        }
    }

cleanup_files:
    for (i = 0; i < sample_count; i++) {
        remove_tree_file(root, samples[i]);
    }
    remove(db_path);
    flb_test_rmdir(root);
    flb_free(root);
}
#endif

void flb_test_recursive_glob_star()
{
#ifdef FLB_HAVE_SQLDB
    struct blob_expect expect[] = {
        {"top.bin", FLB_TRUE},
        {"plain", FLB_TRUE},
        {"subfolder/c.bin", FLB_TRUE},
        {"subfolder/nested/deep.bin", FLB_TRUE},
        {"v1.2/notes.txt", FLB_TRUE},
        {"v1.2/data.bin", FLB_TRUE}
    };

    test_recursive_glob("/**/*", "subfolder/c.bin",
                        expect, sizeof(expect) / sizeof(expect[0]));
#else
    TEST_MSG("SQLDB is required to verify in_blob file registration");
    TEST_CHECK(0);
#endif
}

void flb_test_recursive_glob_dot_directory()
{
#ifdef FLB_HAVE_SQLDB
    struct blob_expect expect[] = {
        {"top.bin", FLB_TRUE},
        {"plain", FLB_FALSE},
        {"subfolder/c.bin", FLB_TRUE},
        {"subfolder/nested/deep.bin", FLB_TRUE},
        {"v1.2/notes.txt", FLB_TRUE},
        {"v1.2/data.bin", FLB_TRUE}
    };

    test_recursive_glob("/**/*.*", "v1.2/notes.txt",
                        expect, sizeof(expect) / sizeof(expect[0]));
#else
    TEST_MSG("SQLDB is required to verify in_blob file registration");
    TEST_CHECK(0);
#endif
}

void flb_test_non_recursive_glob()
{
#ifdef FLB_HAVE_SQLDB
    struct blob_expect expect[] = {
        {"top.bin", FLB_TRUE},
        {"plain", FLB_FALSE},
        {"subfolder/c.bin", FLB_FALSE},
        {"subfolder/nested/deep.bin", FLB_FALSE},
        {"v1.2/notes.txt", FLB_FALSE},
        {"v1.2/data.bin", FLB_FALSE}
    };

    test_recursive_glob("/*.bin", "top.bin",
                        expect, sizeof(expect) / sizeof(expect[0]));
#else
    TEST_MSG("SQLDB is required to verify in_blob file registration");
    TEST_CHECK(0);
#endif
}

TEST_LIST = {
    {"recursive_glob_star", flb_test_recursive_glob_star},
    {"recursive_glob_dot_directory", flb_test_recursive_glob_dot_directory},
    {"non_recursive_glob", flb_test_non_recursive_glob},
    {NULL, NULL}
};
