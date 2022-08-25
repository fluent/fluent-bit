/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

/*
 * This file contains compatibility functions and macros for various platforms.
 *
 * Including this header file should make platforms behave more consistently;
 * Add more macros if you find any missing features.
 */

#ifndef FLB_COMPAT_H
#define FLB_COMPAT_H

/*
 * libmonkey exposes compat macros for <unistd.h>, which some platforms lack,
 * so include the header here.
 */
#include <monkey/mk_core.h>

#ifdef FLB_SYSTEM_WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <Wincrypt.h> /* flb_io_tls.c */

#include <monkey/mk_core/mk_sleep.h>
#include <fluent-bit/flb_dlfcn_win32.h>

#define FLB_DIRCHAR '\\'
#define PATH_MAX MAX_PATH
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISLNK(m) (0)  /* Windows doesn't support S_IFLNK */
#define SHUT_RD   SD_RECEIVE
#define SHUT_WR   SD_SEND
#define SHUT_RDWR SD_BOTH

/* monkey exposes a broken vsnprintf macro. Undo it  */
#undef vsnprintf

/*
 * Windows prefer to add an underscore to each POSIX function.
 * To suppress compiler warnings, we need these trivial macros.
 */
#define timezone _timezone
#define tzname _tzname
#define strncasecmp _strnicmp
#define timegm _mkgmtime

static inline int getpagesize(void)
{
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return info.dwPageSize;
}

static inline struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
    if (gmtime_s(result, timep)) {
        return NULL;
    }
    return result;
}

static inline char *ctime_r(const time_t *timep, char *result)
{
    char *tmp = ctime(timep);
    if (tmp == NULL) {
        return NULL;
    }
    return strcpy(result, tmp);
}

/*
 * We can't just define localtime_r here, since mk_core/mk_utils.c is
 * exposing a symbol with the same name inadvertently.
 */
static struct tm *flb_localtime_r(time_t *timep, struct tm *result)
{
    if (localtime_s(result, timep)) {
        return NULL;
    }
    return result;
}
#define localtime_r flb_localtime_r

static inline char* basename(const char *path)
{
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    char fname[_MAX_FNAME];
    char ext[_MAX_EXT];
    static char buf[_MAX_PATH];

    _splitpath_s(path, drive, _MAX_DRIVE, dir, _MAX_DIR,
                       fname, _MAX_FNAME, ext, _MAX_EXT);

    _makepath_s(buf, _MAX_PATH, "", "", fname, ext);
    return buf;
}

static inline char* realpath(char *path, char *buf)
{
    if (buf != NULL) {
        return NULL;  /* Read BUGS in realpath(3) */
    }
    return _fullpath(NULL, path, 0);
}

static inline int usleep(LONGLONG usec)
{
    // Convert into 100ns unit.
    return nanosleep(usec * 10);
}
#else
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <libgen.h>
#include <dlfcn.h>

#define FLB_DIRCHAR '/'
#endif

#ifdef FLB_HAVE_UNIX_SOCKET
#include <sys/un.h>
#endif

#endif
