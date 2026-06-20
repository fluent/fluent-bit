/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018 Eduardo Silva <eduardo@monkey.io>
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

#ifndef CHUNKIO_COMPAT_H
#define CHUNKIO_COMPAT_H

#include <chunkio/cio_info.h>

#ifdef _WIN32
#include <sys/types.h>
#include <sys/stat.h>
#include <winsock2.h>
#include <windows.h>
#include <aclapi.h>
#include <io.h>
#include <direct.h>
#pragma comment(lib, "ws2_32.lib")

/** mode flags for access() */
#define R_OK 04
#define W_OK 02
#define X_OK 01
#define F_OK 00

#define PATH_MAX MAX_PATH
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define strerror_r(errno,buf,len) strerror_s(buf,len,errno)

typedef SSIZE_T ssize_t;
typedef unsigned mode_t;

static inline char* dirname(const char *path)
{
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    char fname[_MAX_FNAME];
    char ext[_MAX_EXT];
    static char buf[_MAX_PATH];

    _splitpath_s(path, drive, _MAX_DRIVE, dir, _MAX_DIR,
                       fname, _MAX_FNAME, ext, _MAX_EXT);

    _makepath_s(buf, _MAX_PATH, drive, dir, "", "");

    /*
     * If path does not contain a separator, dirname() must
     * return the string ".".
     */
    if (strlen(buf) == 0) {
        strcpy_s(buf, _MAX_PATH, ".");
    }

    return buf;
}

#ifndef CIO_HAVE_GETPAGESIZE
static inline int cio_getpagesize(void)
{
    SYSTEM_INFO system_info;
    GetSystemInfo(&system_info);
    return system_info.dwPageSize;
}
#else
static inline int cio_getpagesize(void)
{
    return getpagesize();
}
#endif

#else
#include <unistd.h>
#include <libgen.h>
#include <dirent.h>
#include <arpa/inet.h>
#endif

#endif
