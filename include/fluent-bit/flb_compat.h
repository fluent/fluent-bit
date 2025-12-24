/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <stdint.h>
#include <fluent-bit/flb_endian.h>

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
#define strcasecmp _stricmp
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
#include <strings.h>

#define FLB_DIRCHAR '/'
#endif

#ifdef FLB_HAVE_UNIX_SOCKET
#include <sys/un.h>
#endif

#ifdef FLB_ENFORCE_ALIGNMENT

/* Please do not modify these functions without a very solid understanding of
 * the reasoning behind.
 *
 * These functions deliverately abuse the volatile qualifier in order to prevent
 * the compiler from mistakenly optimizing the memory accesses into a singled
 * DWORD read (which in some architecture and compiler combinations it does regardless
 * of the flags).
 *
 * The reason why we decided to include this is that according to PR 9096,
 * when the linux kernel is built and configured to pass through memory alignment
 * exceptions rather than remediate them fluent-bit generates one while accessing a
 * packed field in the msgpack wire format (which we cannot modify due to interoperability
 * reasons).
 *
 * Because of this, a potential patch using memcpy was suggested, however, this patch did
 * not yield consistent machine code accross architecture and compiler versions with most
 * of them still generating optimized misaligned memory access instructions.
 *
 * Keep in mind that these functions transform a single memory read into seven plus a few
 * writes as this was the only way to prevent the compiler from mistakenly optimizing the
 * operations.
 *
 * In most cases, FLB_ENFORCE_ALIGNMENT should not be enabled and the operating system
 * kernel should be left to handle these scenarios, however, this option is present for
 * those users who deliverately and knowingly choose to set up their operating system in
 * a way that requires it.
 *
 */

#if FLB_BYTE_ORDER == FLB_LITTLE_ENDIAN
static inline uint32_t __attribute__((optimize("-O0"))) FLB_ALIGNED_DWORD_READ(unsigned char *source) {
    volatile uint32_t result;

    result  = ((uint32_t)(((uint8_t *) source)[0]) <<  0);
    result |= ((uint32_t)(((uint8_t *) source)[1]) <<  8);
    result |= ((uint32_t)(((uint8_t *) source)[2]) << 16);
    result |= ((uint32_t)(((uint8_t *) source)[3]) << 24);

    return result;
}
#else
static inline uint32_t __attribute__((optimize("-O0"))) FLB_ALIGNED_DWORD_READ(unsigned char *source) {
    volatile uint32_t result;

    result  = ((uint32_t)(((uint8_t *) source)[3]) <<  0);
    result |= ((uint32_t)(((uint8_t *) source)[2]) <<  8);
    result |= ((uint32_t)(((uint8_t *) source)[1]) << 16);
    result |= ((uint32_t)(((uint8_t *) source)[0]) << 24);

    return result;
}
#endif

#else
static inline uint32_t FLB_ALIGNED_DWORD_READ(unsigned char *source) {
    return *((uint32_t *) source);
}
#endif

#endif
