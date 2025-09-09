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
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_sds.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "flb_tests_internal.h"

/* https://github.com/fluent/fluent-bit/issues/6313 */
void test_translate_long_env()
{
    struct flb_env *env;
    flb_sds_t buf = NULL;
    char *long_env = "ABC_APPLICATION_TEST_TEST_ABC_FLUENT_BIT_SECRET_FLUENTD_HTTP_HOST";
    char long_env_ra[4096] = {0};
    char *env_val = "aaaaa";
    char putenv_arg[4096] = {0};
    size_t ret_size;
    int ret;

    ret_size = snprintf(&long_env_ra[0], sizeof(long_env_ra), "${%s}", long_env);
    if (!TEST_CHECK(ret_size < sizeof(long_env_ra))) {
        TEST_MSG("long_env_ra size error");
        exit(1);
    }
    ret_size = snprintf(&putenv_arg[0], sizeof(putenv_arg), "%s=%s", long_env, env_val);
    if (!TEST_CHECK(ret_size < sizeof(long_env_ra))) {
        TEST_MSG("putenv_arg size error");
        exit(1);
    }

    env = flb_env_create();
    if (!TEST_CHECK(env != NULL)) {
        TEST_MSG("flb_env_create failed");
        exit(1);
    }
#ifndef FLB_SYSTEM_WINDOWS
    ret = putenv(&putenv_arg[0]);
#else
    ret = _putenv(&putenv_arg[0]);
#endif
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("setenv failed");
        flb_env_destroy(env);
        exit(1);
    }

    buf = flb_env_var_translate(env, &long_env_ra[0]);
    if (!TEST_CHECK(buf != NULL)) {
        TEST_MSG("flb_env_var_translate failed");
#ifndef FLB_SYSTEM_WINDOWS
        unsetenv(long_env);
#endif
        flb_env_destroy(env);
        exit(1);
    }

    if (!TEST_CHECK(strlen(buf) == strlen(env_val) && 0 == strcmp(buf, env_val))) {
        TEST_MSG("mismatch. Got=%s expect=%s", buf, env_val);
    }
    flb_sds_destroy(buf);
#ifndef FLB_SYSTEM_WINDOWS
    unsetenv(long_env);
#endif
    flb_env_destroy(env);
}

/* Test file-based environment variable with refresh interval */
void test_file_env_var_basic()
{
    struct flb_env *env;
    flb_sds_t buf = NULL;
    char *test_file = "/tmp/flb_test_secret.txt";
    char *test_content = "secret_value_123";
    char *template = "${SECRET}";
    int fd;
    int ret;

    /* Create test file */
    fd = open(test_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (!TEST_CHECK(fd >= 0)) {
        TEST_MSG("Failed to create test file");
        return;
    }
    ret = write(fd, test_content, strlen(test_content));
    close(fd);
    if (!TEST_CHECK(ret == strlen(test_content))) {
        TEST_MSG("Failed to write test content");
        unlink(test_file);
        return;
    }

    /* Test environment variable loading */
    env = flb_env_create();
    if (!TEST_CHECK(env != NULL)) {
        TEST_MSG("flb_env_create failed");
        unlink(test_file);
        return;
    }

    /* Set file-based environment variable */
    ret = flb_env_set_extended(env, "SECRET", NULL, "file:///tmp/flb_test_secret.txt", 0);
    if (!TEST_CHECK(ret >= 0)) {
        TEST_MSG("flb_env_set_extended failed");
        flb_env_destroy(env);
        unlink(test_file);
        return;
    }

    /* Test variable translation */
    buf = flb_env_var_translate(env, template);
    if (!TEST_CHECK(buf != NULL)) {
        TEST_MSG("flb_env_var_translate failed");
        flb_env_destroy(env);
        unlink(test_file);
        return;
    }

    if (!TEST_CHECK(strcmp(buf, test_content) == 0)) {
        TEST_MSG("Content mismatch. Got=%s expect=%s", buf, test_content);
    }

    flb_sds_destroy(buf);
    flb_env_destroy(env);
    unlink(test_file);
}

/* Test file-based environment variable with refresh interval */
void test_file_env_var_refresh()
{
    struct flb_env *env;
    flb_sds_t buf = NULL;
    char *test_file = "/tmp/flb_test_refresh.txt";
    char *initial_content = "initial_value";
    char *updated_content = "updated_value";
    char *template = "${REFRESH_VAR}";
    int fd;
    int ret;

    /* Create test file with initial content */
    fd = open(test_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (!TEST_CHECK(fd >= 0)) {
        TEST_MSG("Failed to create test file");
        return;
    }
    ret = write(fd, initial_content, strlen(initial_content));
    close(fd);
    if (!TEST_CHECK(ret == strlen(initial_content))) {
        TEST_MSG("Failed to write initial content");
        unlink(test_file);
        return;
    }

    /* Test environment variable loading with refresh interval */
    env = flb_env_create();
    if (!TEST_CHECK(env != NULL)) {
        TEST_MSG("flb_env_create failed");
        unlink(test_file);
        return;
    }

    /* Set file-based environment variable with 1 second refresh interval */
    ret = flb_env_set_extended(env, "REFRESH_VAR", NULL, "file:///tmp/flb_test_refresh.txt", 1);
    if (!TEST_CHECK(ret >= 0)) {
        TEST_MSG("flb_env_set_extended failed");
        flb_env_destroy(env);
        unlink(test_file);
        return;
    }

    /* Test initial value */
    buf = flb_env_var_translate(env, template);
    if (!TEST_CHECK(buf != NULL)) {
        TEST_MSG("flb_env_var_translate failed");
        flb_env_destroy(env);
        unlink(test_file);
        return;
    }

    if (!TEST_CHECK(strcmp(buf, initial_content) == 0)) {
        TEST_MSG("Initial content mismatch. Got=%s expect=%s", buf, initial_content);
    }
    flb_sds_destroy(buf);

    /* Update file content */
    fd = open(test_file, O_WRONLY | O_TRUNC, 0644);
    if (!TEST_CHECK(fd >= 0)) {
        TEST_MSG("Failed to open test file for update");
        flb_env_destroy(env);
        unlink(test_file);
        return;
    }
    ret = write(fd, updated_content, strlen(updated_content));
    close(fd);
    if (!TEST_CHECK(ret == strlen(updated_content))) {
        TEST_MSG("Failed to write updated content");
        flb_env_destroy(env);
        unlink(test_file);
        return;
    }

    /* Wait for refresh interval to pass */
    sleep(2);

    /* Test updated value */
    buf = flb_env_var_translate(env, template);
    if (!TEST_CHECK(buf != NULL)) {
        TEST_MSG("flb_env_var_translate failed after refresh");
        flb_env_destroy(env);
        unlink(test_file);
        return;
    }

    if (!TEST_CHECK(strcmp(buf, updated_content) == 0)) {
        TEST_MSG("Updated content mismatch. Got=%s expect=%s", buf, updated_content);
    }

    flb_sds_destroy(buf);
    flb_env_destroy(env);
    unlink(test_file);
}

/* Test file-based environment variable with file:// URI */
void test_file_env_var_uri()
{
    struct flb_env *env;
    flb_sds_t buf = NULL;
    char *test_file = "/tmp/flb_test_uri.txt";
    char *test_content = "uri_value_456";
    char *file_uri = "file:///tmp/flb_test_uri.txt";
    char *template = "${URI_VAR}";
    int fd;
    int ret;

    /* Create test file */
    fd = open(test_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (!TEST_CHECK(fd >= 0)) {
        TEST_MSG("Failed to create test file");
        return;
    }
    ret = write(fd, test_content, strlen(test_content));
    close(fd);
    if (!TEST_CHECK(ret == strlen(test_content))) {
        TEST_MSG("Failed to write test content");
        unlink(test_file);
        return;
    }

    /* Test environment variable loading with file:// URI */
    env = flb_env_create();
    if (!TEST_CHECK(env != NULL)) {
        TEST_MSG("flb_env_create failed");
        unlink(test_file);
        return;
    }

    /* Set file-based environment variable with file:// URI */
    ret = flb_env_set_extended(env, "URI_VAR", NULL, file_uri, 0);
    if (!TEST_CHECK(ret >= 0)) {
        TEST_MSG("flb_env_set_extended failed");
        flb_env_destroy(env);
        unlink(test_file);
        return;
    }

    /* Test variable translation */
    buf = flb_env_var_translate(env, template);
    if (!TEST_CHECK(buf != NULL)) {
        TEST_MSG("flb_env_var_translate failed");
        flb_env_destroy(env);
        unlink(test_file);
        return;
    }

    if (!TEST_CHECK(strcmp(buf, test_content) == 0)) {
        TEST_MSG("Content mismatch. Got=%s expect=%s", buf, test_content);
    }

    flb_sds_destroy(buf);
    flb_env_destroy(env);
    unlink(test_file);
}

/* Test mixed static and dynamic environment variables */
void test_mixed_env_vars()
{
    struct flb_env *env;
    flb_sds_t buf = NULL;
    char *test_file = "/tmp/flb_test_mixed.txt";
    char *file_content = "dynamic_value";
    char *template = "Static: ${STATIC_VAR}, Dynamic: ${DYNAMIC_VAR}";
    char *expected = "Static: static_value, Dynamic: dynamic_value";
    int fd;
    int ret;

    /* Create test file */
    fd = open(test_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (!TEST_CHECK(fd >= 0)) {
        TEST_MSG("Failed to create test file");
        return;
    }
    ret = write(fd, file_content, strlen(file_content));
    close(fd);
    if (!TEST_CHECK(ret == strlen(file_content))) {
        TEST_MSG("Failed to write test content");
        unlink(test_file);
        return;
    }

    /* Test mixed environment variables */
    env = flb_env_create();
    if (!TEST_CHECK(env != NULL)) {
        TEST_MSG("flb_env_create failed");
        unlink(test_file);
        return;
    }

    /* Set static environment variable */
    ret = flb_env_set(env, "STATIC_VAR", "static_value");
    if (!TEST_CHECK(ret >= 0)) {
        TEST_MSG("flb_env_set failed for static variable");
        flb_env_destroy(env);
        unlink(test_file);
        return;
    }

    /* Set dynamic environment variable */
    ret = flb_env_set_extended(env, "DYNAMIC_VAR", NULL, "file:///tmp/flb_test_mixed.txt", 0);
    if (!TEST_CHECK(ret >= 0)) {
        TEST_MSG("flb_env_set_extended failed for dynamic variable");
        flb_env_destroy(env);
        unlink(test_file);
        return;
    }

    /* Test mixed variable translation */
    buf = flb_env_var_translate(env, template);
    if (!TEST_CHECK(buf != NULL)) {
        TEST_MSG("flb_env_var_translate failed");
        flb_env_destroy(env);
        unlink(test_file);
        return;
    }

    if (!TEST_CHECK(strcmp(buf, expected) == 0)) {
        TEST_MSG("Mixed content mismatch. Got=%s expect=%s", buf, expected);
    }

    flb_sds_destroy(buf);
    flb_env_destroy(env);
    unlink(test_file);
}

/* Test error handling for missing file */
void test_file_env_var_missing()
{
    struct flb_env *env;
    flb_sds_t buf = NULL;
    char *missing_file = "/tmp/flb_nonexistent_file.txt";
    char *template = "${MISSING_VAR}";
    int ret;

    /* Test environment variable loading with missing file */
    env = flb_env_create();
    if (!TEST_CHECK(env != NULL)) {
        TEST_MSG("flb_env_create failed");
        return;
    }

    /* Set file-based environment variable with missing file */
    ret = flb_env_set_extended(env, "MISSING_VAR", NULL, "file:///tmp/flb_nonexistent_file.txt", 0);
    if (!TEST_CHECK(ret == -1)) {
        TEST_MSG("flb_env_set_extended failed");
        flb_env_destroy(env);
        return;
    }

    /* Test variable translation should return empty string for missing file */
    buf = flb_env_var_translate(env, template);
    if (!TEST_CHECK(buf != NULL)) {
        TEST_MSG("flb_env_var_translate failed");
        flb_env_destroy(env);
        return;
    }

    /* Should return empty string for missing file */
    if (!TEST_CHECK(strlen(buf) == 0)) {
        TEST_MSG("Expected empty string for missing file. Got=%s", buf);
    }

    flb_sds_destroy(buf);
    flb_env_destroy(env);
}


TEST_LIST = {
    { "translate_long_env"           , test_translate_long_env},
    { "file_env_var_basic"           , test_file_env_var_basic},
    { "file_env_var_refresh"         , test_file_env_var_refresh},
    { "file_env_var_uri"             , test_file_env_var_uri},
    { "mixed_env_vars"               , test_mixed_env_vars},
    { "file_env_var_missing"         , test_file_env_var_missing},
    { NULL, NULL }
};
