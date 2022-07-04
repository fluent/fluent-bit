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

#include "entities.h"

#include <fluent-bit/flb_input_plugin.h>

#include <stdint.h>
#include <time.h>

#define MS_PER_NSEC 1000000
#define NS_PER_SEC 1000000000ULL

typedef struct AndroidLogEntry
{
    time_t tv_sec;
    long tv_nsec;
    android_LogPriority priority;
    int32_t uid;
    int32_t pid;
    int32_t tid;
    const char *tag;
    size_t tagLen;
    size_t messageLen;
    const char *message;
} AndroidLogEntry;

int parseLogEntry(log_msg * buf, int length, AndroidLogEntry * entry,
                  struct flb_input_instance *ins);
char *formatLogLine(char *defaultBuffer, size_t defaultBufferSize,
                    const AndroidLogEntry * entry, size_t * p_outLength);
