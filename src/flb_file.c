/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fluent-bit/flb_file.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_str.h>

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifndef FLB_SYSTEM_WINDOWS
#include <unistd.h>

#if defined(O_PATH)
#define FLB_FILE_SEARCH O_PATH
#elif defined(O_SEARCH)
#define FLB_FILE_SEARCH O_SEARCH
#else
#define FLB_FILE_SEARCH O_RDONLY
#endif
#define FLB_FILE_DIRECTORY_FLAGS (FLB_FILE_SEARCH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
#endif

flb_sds_t flb_file_read(const char *path)
{
    long flen;
    FILE *f = NULL;
    flb_sds_t result = NULL;

    f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) == -1) {
        goto err;
    }

    flen = ftell(f);
    if (flen < 0) {
        goto err;
    }

    if (fseek(f, 0, SEEK_SET) == -1) {
        goto err;
    }

    result = flb_sds_create_size(flen);
    if (!result) {
        goto err;
    }

    if (flen > 0 && fread(result, flen, 1, f) != 1) {
        goto err;
    }

    result[flen] = 0;
    flb_sds_len_set(result, flen);
    fclose(f);
    return result;

err:
    flb_errno();
    fclose(f);
    if (result) {
        flb_sds_destroy(result);
    }
    return NULL;
}

#ifndef FLB_SYSTEM_WINDOWS
/*
 * Walk from a held directory descriptor. O_NOFOLLOW applies to each component,
 * since checking a pathname and opening it later would race.
 */
int flb_file_open_safe(const char *root, const char *path, int flags,
                       int mode, int mkdir_mode)
{
    char *full_path;
    char *component;
    char *next;
    char *cursor;
    char canonical_root[PATH_MAX];
    char canonical_path[PATH_MAX];
    size_t root_len;
    int dir_fd;
    int next_fd;
    int fd = -1;
    int saved_errno;
    int stat_result;
    struct stat st = {0};

    if (path == NULL || path[0] == '\0' ||
        (root != NULL && path[0] == '/')) {
        errno = EINVAL;
        return -1;
    }

    root_len = root == NULL ? 0 : strlen(root);
    full_path = flb_malloc(root_len + strlen(path) + 2);
    if (full_path == NULL) {
        return -1;
    }
    if (root != NULL) {
        sprintf(full_path, "%s" FLB_PATH_SEPARATOR "%s", root, path);

        /* Check component boundaries, so /root-other is not beneath /root. */
        if (realpath(root, canonical_root) == NULL) {
            goto error;
        }
        root_len = strlen(canonical_root);
        if (realpath(full_path, canonical_path) != NULL &&
            (strncmp(canonical_root, canonical_path, root_len) != 0 ||
             (root_len > 1 && canonical_path[root_len] != '/' &&
              canonical_path[root_len] != '\0'))) {
            errno = EACCES;
            goto error;
        }
    }
    else {
        strcpy(full_path, path);
    }

    /* Validate the whole path before creating directories or opening a file. */
    cursor = full_path;
    while (*cursor != '\0') {
        if ((cursor == full_path || cursor[-1] == '/') && cursor[0] == '.' &&
            cursor[1] == '.' && (cursor[2] == '/' || cursor[2] == '\0')) {
            errno = EACCES;
            goto error;
        }
        cursor++;
    }
    if (cursor[-1] == '/') {
        errno = EISDIR;
        goto error;
    }

    dir_fd = open(full_path[0] == '/' ? "/" : ".", FLB_FILE_DIRECTORY_FLAGS);
    if (dir_fd < 0) {
        goto error;
    }
    component = full_path;
    while (*component == '/') {
        component++;
    }
    while ((next = strchr(component, '/')) != NULL) {
        *next = '\0';
        next++;
        if (*component != '\0' && strcmp(component, ".") != 0) {
            next_fd = openat(dir_fd, component, FLB_FILE_DIRECTORY_FLAGS);
            if (next_fd < 0 && errno == ENOENT && mkdir_mode != 0) {
                if (mkdirat(dir_fd, component, mkdir_mode) == 0 || errno == EEXIST) {
                    next_fd = openat(dir_fd, component, FLB_FILE_DIRECTORY_FLAGS);
                }
            }
            if (next_fd < 0) {
                goto close_directory;
            }
            close(dir_fd);
            dir_fd = next_fd;
        }
        component = next;
    }

    /* Delay truncation until the descriptor is known to refer to a regular file.
     * Nonblocking open prevents a substituted FIFO from hanging the engine. */
    fd = openat(dir_fd, component, (flags & ~O_TRUNC) | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, mode);
    if (fd >= 0) {
        stat_result = fstat(fd, &st);
        if (stat_result != 0 ||
            ((flags & O_DIRECTORY) ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode))) {
            saved_errno = stat_result != 0 ? errno : EINVAL;
            close(fd);
            fd = -1;
            errno = saved_errno;
        }
        else if ((flags & O_TRUNC) && ftruncate(fd, 0) != 0) {
            saved_errno = errno;
            close(fd);
            fd = -1;
            errno = saved_errno;
        }
    }

close_directory:
    saved_errno = errno;
    close(dir_fd);
    errno = saved_errno;
error:
    saved_errno = errno;
    flb_free(full_path);
    errno = saved_errno;
    return fd;
}
#endif

FILE *flb_file_fopen_safe(const char *root, const char *path, const char *mode,
                          int mkdir_mode)
{
    int flags;
    int fd;
    int saved_errno;
    FILE *stream;

    if (strchr(mode, 'x') != NULL) {
        errno = EINVAL;
        return NULL;
    }
    if (mode[0] == 'a') {
        flags = O_CREAT | O_APPEND;
    }
    else if (mode[0] == 'w') {
        flags = O_CREAT | O_TRUNC;
    }
    else if (mode[0] == 'r') {
        flags = 0;
    }
    else {
        errno = EINVAL;
        return NULL;
    }
    flags |= strchr(mode, '+') != NULL ? O_RDWR : (mode[0] == 'r' ? O_RDONLY : O_WRONLY);
#ifdef FLB_SYSTEM_WINDOWS
    if (strchr(mode, 'b') == NULL) {
        flags |= O_TEXT;
    }
#endif
    fd = flb_file_open_safe(root, path, flags, 0666, mkdir_mode);
    if (fd < 0) {
        return NULL;
    }
    stream = fdopen(fd, mode);
    if (stream == NULL) {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
    }
    return stream;
}

#ifndef FLB_SYSTEM_WINDOWS
int flb_file_mkdir_safe(const char *path, int mode)
{
    char *directory;
    int fd;

    if (path == NULL || *path == '\0') {
        errno = EINVAL;
        return -1;
    }
    directory = flb_malloc(strlen(path) + 3);
    if (directory == NULL) {
        return -1;
    }
    sprintf(directory, "%s/.", path);
    fd = flb_file_open_safe(NULL, directory, FLB_FILE_SEARCH | O_DIRECTORY, 0, mode);
    flb_free(directory);
    if (fd < 0) {
        return -1;
    }
    close(fd);
    return 0;
}

static int file_parent_open(const char *path, char **copy, char **name)
{
    char *separator;
    const char *parent;
    int fd;

    *copy = flb_strdup(path);
    if (*copy == NULL) {
        return -1;
    }
    separator = strrchr(*copy, '/');
    if (separator == NULL) {
        parent = ".";
        *name = *copy;
    }
    else {
        *separator = '\0';
        *name = separator + 1;
        while (separator > *copy && separator[-1] == '/') {
            *--separator = '\0';
        }
        parent = separator == *copy ? "/." : *copy;
    }
    if (**name == '\0' || strcmp(*name, ".") == 0 || strcmp(*name, "..") == 0) {
        flb_free(*copy);
        errno = EINVAL;
        return -1;
    }
    fd = flb_file_open_safe(NULL, parent, FLB_FILE_SEARCH | O_DIRECTORY, 0, 0);
    if (fd < 0) {
        flb_free(*copy);
    }
    return fd;
}

int flb_file_rename_safe(const char *source, const char *destination)
{
    char *source_copy;
    char *destination_copy;
    char *source_name;
    char *destination_name;
    int source_fd;
    int destination_fd;
    int ret = -1;
    int saved_errno;

    source_fd = file_parent_open(source, &source_copy, &source_name);
    if (source_fd < 0) {
        return -1;
    }
    destination_fd = file_parent_open(destination, &destination_copy, &destination_name);
    if (destination_fd >= 0) {
        /* renameat replaces a destination symlink without following it. */
        ret = renameat(source_fd, source_name, destination_fd, destination_name);
        saved_errno = errno;
        close(destination_fd);
        flb_free(destination_copy);
        errno = saved_errno;
    }
    saved_errno = errno;
    close(source_fd);
    flb_free(source_copy);
    errno = saved_errno;
    return ret;
}

int flb_file_unlink_safe(const char *path)
{
    char *copy;
    char *name;
    int fd;
    int ret;
    int saved_errno;

    fd = file_parent_open(path, &copy, &name);
    if (fd < 0) {
        return -1;
    }
    ret = unlinkat(fd, name, 0);
    saved_errno = errno;
    close(fd);
    flb_free(copy);
    errno = saved_errno;
    return ret;
}
#endif
