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

#include "stdint.h"

/**
 * Android log priority values, in increasing order of priority.
 */
typedef enum android_LogPriority
{
    /** For internal use only.  */
    ANDROID_LOG_UNKNOWN = 0,
    /** The default priority, for internal use only.  */
    ANDROID_LOG_DEFAULT,        /* only for SetMinPriority() */
    /** Verbose logging. Should typically be disabled for a release apk. */
    ANDROID_LOG_VERBOSE,
    /** Debug logging. Should typically be disabled for a release apk. */
    ANDROID_LOG_DEBUG,
    /** Informational logging. Should typically be disabled for a release apk. */
    ANDROID_LOG_INFO,
    /** Warning logging. For use with recoverable failures. */
    ANDROID_LOG_WARN,
    /** Error logging. For use with unrecoverable failures. */
    ANDROID_LOG_ERROR,
    /** Fatal logging. For use when aborting. */
    ANDROID_LOG_FATAL,
    /** For internal use only.  */
    ANDROID_LOG_SILENT,         /* only for SetMinPriority(); must be last */
} android_LogPriority;

/**
 * Identifies a specific log buffer for __android_log_buf_write()
 * and __android_log_buf_print().
 */
typedef enum log_id
{
    LOG_ID_MIN = 0,

    /** The main log buffer. This is the only log buffer available to apps. */
    LOG_ID_MAIN = 0,
    /** The radio log buffer. */
    LOG_ID_RADIO = 1,
    /** The event log buffer. */
    LOG_ID_EVENTS = 2,
    /** The system log buffer. */
    LOG_ID_SYSTEM = 3,
    /** The crash log buffer. */
    LOG_ID_CRASH = 4,
    /** The statistics log buffer. */
    LOG_ID_STATS = 5,
    /** The security log buffer. */
    LOG_ID_SECURITY = 6,
    /** The kernel log buffer. */
    LOG_ID_KERNEL = 7,

    LOG_ID_MAX,

    /** Let the logging function choose the best log target. */
    LOG_ID_DEFAULT = 0x7FFFFFFF
} log_id;

#define LOGGER_ENTRY_MAX_LEN 5 * 1024

typedef struct logger_entry
{
    uint16_t len;               /* length of the payload */
    uint16_t hdr_size;          /* sizeof(struct logger_entry) */
    int32_t pid;                /* generating process's pid */
    uint32_t tid;               /* generating process's tid */
    uint32_t sec;               /* seconds since Epoch */
    uint32_t nsec;              /* nanoseconds */
    uint32_t lid;               /* log id of the payload, bottom 4 bits currently */
    uint32_t uid;               /* generating process's uid */
} logger_entry;

typedef struct log_msg
{
    union
    {
        char buf[LOGGER_ENTRY_MAX_LEN + 1];
        struct logger_entry entry;
    } __attribute__ ((aligned(4)));
} log_msg;
