/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
 *  Copyright (C) 2005-2017 The Android Open Source Project
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

#pragma once

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include "logprint.h"

#define DEFAULT_SOCKET_PATH "/dev/socket/logdr"
#define DEFAULT_CONTROL_SOCKET_PATH "/dev/socket/logd"
#define DEFAULT_LOG_BUFFER_SIZE "1048576"       /* 1 MB */

const int MAX_COMMAND_RESPONSE_LEN = 32;
const int MAX_COMMAND_LEN = 64;

const int MIN_DELAY_SEC = 1;
const int MAX_DELAY_SEC = 32;
const int DELAY_AMPLIFY = 2;

struct flb_logcat
{
    struct flb_input_instance *ins;
    int server_fd;
    char *path;
    char *socket_path;
    char *control_socket_path;
    int log_buffer_size;
    int collector_id;
};

#define report_error(ctx, fmt, ...)                \
    flb_plg_error((ctx)->ins, fmt, ##__VA_ARGS__); \
    output_error_as_log((ctx), fmt, ##__VA_ARGS__)

extern int output_error_as_log(struct flb_logcat *ctx, const char *fmt, ...);

typedef enum control_command_result
{
    SUCCESS = 0,
    PERMISSION_DENIED = 1,
    INTERNAL_ERROR = 2
} control_command_result;

extern struct flb_input_plugin in_logcat_plugin;
