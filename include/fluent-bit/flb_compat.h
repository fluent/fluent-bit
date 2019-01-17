/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#ifndef FLB_COMPAT_H
#define FLB_COMPAT_H

/* libmonkey exposes compat macros for <unistd.h> */
#include <monkey/mk_core.h>

/* Windows compatibility utils */
#ifdef _MSC_VER
#define PATH_MAX MAX_PATH

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>

static inline int getpagesize(void)
{
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return info.dwPageSize;
}

static inline struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
    if (gmtime_s(result, timep))
        return NULL;
    return result;
}

/* mk_utils.c exposes localtime_r */
extern struct tm *localtime_r(const time_t *timep, struct tm * result);

#else
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#endif
