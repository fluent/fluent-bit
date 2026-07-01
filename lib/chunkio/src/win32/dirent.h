/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018-2019 Eduardo Silva <eduardo@monkey.io>
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
 * POSIX <dirent.h> emulation for Windows.
 *
 * This header file provies a drop-in replacement of opendir(),
 * readdir() and closedir() for Windows platform.
 */

#ifndef CIO_WIN32_DIRENT
#define CIO_WIN32_DIRENT

struct CIO_WIN32_DIR;

struct cio_win32_dirent {
    int d_ino;
    int d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char *d_name;
};

struct CIO_WIN32_DIR *cio_win32_opendir(const char *path);
struct cio_win32_dirent *cio_win32_readdir(struct CIO_WIN32_DIR *d);
int cio_win32_closedir(struct CIO_WIN32_DIR *d);

#define DIR struct CIO_WIN32_DIR
#define dirent cio_win32_dirent
#define closedir cio_win32_closedir
#define opendir cio_win32_opendir
#define readdir cio_win32_readdir

#define DT_UNKNOWN -1
#define DT_BLK      1
#define DT_CHR      2
#define DT_DIR      3
#define DT_FIFO     4
#define DT_LNK      5
#define DT_REG      6
#define DT_SOCK     7

#endif
