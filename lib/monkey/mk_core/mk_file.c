/*-*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "mk_core.h"

#ifdef _WIN32
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISLNK(m) (0)
#define O_NONBLOCK (0)
#define lstat stat
#endif

int mk_file_get_info(const char *path, struct file_info *f_info, int mode)
{
    struct stat f, target;

    f_info->exists = MK_FALSE;

    /* Stat right resource */
    if (lstat(path, &f) == -1) {
        if (errno == EACCES) {
            f_info->exists = MK_TRUE;
        }
        return -1;
    }

    f_info->exists = MK_TRUE;
    f_info->is_file = MK_TRUE;
    f_info->is_link = MK_FALSE;
    f_info->is_directory = MK_FALSE;
    f_info->exec_access = MK_FALSE;
    f_info->read_access = MK_FALSE;

    if (S_ISLNK(f.st_mode)) {
        f_info->is_link = MK_TRUE;
        f_info->is_file = MK_FALSE;
        if (stat(path, &target) == -1) {
            return -1;
        }
    }
    else {
        target = f;
    }

    f_info->size = target.st_size;
    f_info->last_modification = target.st_mtime;

    if (S_ISDIR(target.st_mode)) {
        f_info->is_directory = MK_TRUE;
        f_info->is_file = MK_FALSE;
    }

#ifndef _WIN32
    gid_t EGID = getegid();
    gid_t EUID = geteuid();

    /* Check read access */
    if (mode & MK_FILE_READ) {
        if (((target.st_mode & S_IRUSR) && target.st_uid == EUID) ||
            ((target.st_mode & S_IRGRP) && target.st_gid == EGID) ||
            (target.st_mode & S_IROTH)) {
            f_info->read_access = MK_TRUE;
        }
    }

    /* Checking execution */
    if (mode & MK_FILE_EXEC) {
        if ((target.st_mode & S_IXUSR && target.st_uid == EUID) ||
            (target.st_mode & S_IXGRP && target.st_gid == EGID) ||
            (target.st_mode & S_IXOTH)) {
            f_info->exec_access = MK_TRUE;
        }
    }
#endif

    /* Suggest open(2) flags */
    f_info->flags_read_only = O_RDONLY | O_NONBLOCK;

#if defined(__linux__)
    /*
     * If the user is the owner of the file or the user is root, it
     * can set the O_NOATIME flag for open(2) operations to avoid
     * inode updates about last accessed time
     */
    if (target.st_uid == EUID || EUID == 0) {
        f_info->flags_read_only |=  O_NOATIME;
    }
#endif

    return 0;
}

/* Read file content to a memory buffer,
 * Use this function just for really SMALL files
 */
char *mk_file_to_buffer(const char *path)
{
    FILE *fp;
    char *buffer;
    long bytes;
    struct file_info finfo;

    if (mk_file_get_info(path, &finfo, MK_FILE_READ) != 0) {
        return NULL;
    }

    if (!(fp = fopen(path, "rb"))) {
        return NULL;
    }

    buffer = mk_mem_alloc_z(finfo.size + 1);
    if (!buffer) {
        fclose(fp);
        return NULL;
    }

    bytes = fread(buffer, finfo.size, 1, fp);

    if (bytes < 1) {
        mk_mem_free(buffer);
        fclose(fp);
        return NULL;
    }

    fclose(fp);
    return (char *) buffer;

}
