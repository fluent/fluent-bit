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

#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>

#ifndef FLB_SYSTEM_WINDOWS
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "flb_tests_internal.h"

#define ENV_LOG_LEVEL "FLB_LOG_LEVEL"

#ifdef FLB_SYSTEM_WINDOWS
static int flb_test_setenv(const char *name, const char *value, int overwrite)
{
    if (overwrite == 0 && getenv(name) != NULL) {
        return 0;
    }

    return _putenv_s(name, value);
}

static int flb_test_unsetenv(const char *name)
{
    return _putenv_s(name, "");
}
#else
#define flb_test_setenv(name, value, overwrite) setenv(name, value, overwrite)
#define flb_test_unsetenv(name) unsetenv(name)
#endif

static char *save_env_log_level()
{
    char *val;

    val = getenv(ENV_LOG_LEVEL);
    if (val != NULL && val[0] != '\0') {
        return strdup(val);
    }
    return NULL;
}

static void restore_env_log_level(char *saved)
{
    if (saved != NULL) {
        flb_test_setenv(ENV_LOG_LEVEL, saved, 1);
        free(saved);
    }
    else {
        flb_test_unsetenv(ENV_LOG_LEVEL);
    }
}

/*
 * Regression test for GitHub issue #12310: when FLB_LOG_LEVEL is set in the
 * environment and log_level is also present in the [SERVICE] section,
 * flb_config_set_property() must return success (the environment variable
 * takes precedence). Before the fix it returned -1 on this path, which
 * since 5.1.0 aborted startup.
 */
static void test_log_level_env_and_config()
{
    int ret;
    char *saved;
    struct flb_config *config;

    saved = save_env_log_level();

    ret = flb_test_setenv(ENV_LOG_LEVEL, "debug", 1);
    TEST_CHECK(ret == 0);

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config == NULL) {
        restore_env_log_level(saved);
        return;
    }

    ret = flb_config_set_property(config, "log_level", "info");
    TEST_CHECK(ret == 0);
    TEST_MSG("flb_config_set_property returned %d, expected 0", ret);

#ifndef FLB_HAVE_STATIC_CONF
    /* the environment variable wins over the configuration value */
    TEST_CHECK(config->verbose == FLB_LOG_DEBUG);
    TEST_MSG("verbose is %d, expected %d (debug)",
             config->verbose, FLB_LOG_DEBUG);
#endif

    flb_config_exit(config);
    restore_env_log_level(saved);
}

static void test_log_level_config_only()
{
    int ret;
    char *saved;
    struct flb_config *config;

    saved = save_env_log_level();
    flb_test_unsetenv(ENV_LOG_LEVEL);

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config == NULL) {
        restore_env_log_level(saved);
        return;
    }

    ret = flb_config_set_property(config, "log_level", "info");
    TEST_CHECK(ret == 0);
    TEST_CHECK(config->verbose == FLB_LOG_INFO);

    /* an invalid value must still be reported as an error */
    ret = flb_config_set_property(config, "log_level", "invalid_level");
    TEST_CHECK(ret == -1);

    flb_config_exit(config);
    restore_env_log_level(saved);
}

static void test_channel_initialization(void)
{
    struct flb_config *config;
    struct flb_input_instance *input;
    struct flb_output_instance *output;

    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    TEST_CHECK(config->ch_data[0] == FLB_UNINITIALIZED_SOCKET);
    TEST_CHECK(config->ch_data[1] == FLB_UNINITIALIZED_SOCKET);
    TEST_CHECK(config->ch_manager[0] == FLB_UNINITIALIZED_SOCKET);
    TEST_CHECK(config->ch_manager[1] == FLB_UNINITIALIZED_SOCKET);
    TEST_CHECK(config->ch_notif[0] == FLB_UNINITIALIZED_SOCKET);
    TEST_CHECK(config->ch_notif[1] == FLB_UNINITIALIZED_SOCKET);
    input = flb_input_new(config, "dummy", NULL, FLB_FALSE);
    TEST_ASSERT(input != NULL);
    TEST_CHECK(input->ch_events[0] == FLB_UNINITIALIZED_SOCKET);
    TEST_CHECK(input->ch_events[1] == FLB_UNINITIALIZED_SOCKET);
    output = flb_output_new(config, "null", NULL, FLB_FALSE);
    TEST_ASSERT(output != NULL);
    TEST_CHECK(output->ch_events[0] == FLB_UNINITIALIZED_SOCKET);
    TEST_CHECK(output->ch_events[1] == FLB_UNINITIALIZED_SOCKET);
    flb_input_instance_destroy(input);
    flb_output_instance_destroy(output);
    flb_config_exit(config);
}

#ifndef FLB_SYSTEM_WINDOWS
/* A missing read end must not prevent release of an owned write end. */
static void test_partial_config_channels(void)
{
    int channel[2];
    int kind;
    struct flb_config *config;

    for (kind = 0; kind < 2; kind++) {
        config = flb_config_init();
        TEST_ASSERT(config != NULL);
        TEST_ASSERT(pipe(channel) == 0);
        close(channel[0]);
        if (kind == 0) {
            config->ch_manager[1] = channel[1];
        }
        else {
            config->ch_notif[1] = channel[1];
        }
        flb_config_exit(config);
        errno = 0;
        TEST_CHECK(fcntl(channel[1], F_GETFD) == -1 && errno == EBADF);
    }
}


#endif

TEST_LIST = {
    { "channel_initialization", test_channel_initialization },
#ifndef FLB_SYSTEM_WINDOWS
    { "partial_config_channels", test_partial_config_channels },
#endif
    { "log_level_env_and_config", test_log_level_env_and_config },
    { "log_level_config_only",    test_log_level_config_only },
    { 0 }
};
