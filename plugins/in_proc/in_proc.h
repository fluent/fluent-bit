/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#ifndef FLB_IN_PROC_H
#define FLB_IN_PROC_H

#include <stdint.h>
#include <unistd.h>
#include <fluent-bit/flb_input.h>
#include <msgpack.h>

#define DEFAULT_INTERVAL_SEC  1
#define DEFAULT_INTERVAL_NSEC 0

#define FLB_CMD_LEN 256
#define FLB_IN_PROC_NAME "in_proc"
struct flb_in_proc_config {
    uint8_t  alert;

    /* Checking process */
    char*  proc_name;
    pid_t  pid;
    size_t len_proc_name;

    /* Time interval check */
    int interval_sec;
    int interval_nsec;
};

extern struct flb_input_plugin in_proc_plugin;

#endif /*FLB_IN_PROC_H*/
