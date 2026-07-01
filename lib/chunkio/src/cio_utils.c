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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#ifndef _MSC_VER
#include <fts.h>
#endif

#include <chunkio/cio_info.h>
#include <chunkio/chunkio_compat.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_log.h>

#ifndef _MSC_VER
/*
 * Taken from StackOverflow:
 *
 * https://stackoverflow.com/questions/2256945/removing-a-non-empty-directory-programmatically-in-c-or-c
 */
int cio_utils_recursive_delete(const char *dir)
{
    int ret = 0;
    FTS *ftsp = NULL;
    FTSENT *curr;
    char *files[] = { (char *) dir, NULL };
    struct stat st;

    ret = stat(dir, &st);
    if (ret == -1) {
        return -1;
    }

    ftsp = fts_open(files, FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV, NULL);
    if (!ftsp) {
        fprintf(stderr, "%s: fts_open failed: %s\n", dir, strerror(errno));
        ret = -1;
        goto finish;
    }

    while ((curr = fts_read(ftsp))) {
        switch (curr->fts_info) {
        case FTS_NS:
        case FTS_DNR:
        case FTS_ERR:
            fprintf(stderr, "%s: fts_read error: %s\n",
                    curr->fts_accpath, strerror(curr->fts_errno));
            break;
        case FTS_DC:
        case FTS_DOT:
        case FTS_NSOK:
            break;
        case FTS_D:
            break;
        case FTS_DP:
        case FTS_F:
        case FTS_SL:
        case FTS_SLNONE:
        case FTS_DEFAULT:
            if (remove(curr->fts_accpath) < 0) {
                fprintf(stderr, "%s: Failed to remove: %s\n",
                        curr->fts_path, strerror(errno));
                ret = -1;
            }
            break;
        }
    }

 finish:
    if (ftsp) {
        fts_close(ftsp);
    }

    return ret;
}
#else
static int cio_utils_recursive_delete_handler(const char *path,
                                              size_t current_depth,
                                              size_t depth_limit)
{
    char             search_path[MAX_PATH];
    char             entry_path[MAX_PATH];
    DWORD            target_file_flags;
    HANDLE           find_file_handle;
    WIN32_FIND_DATAA find_file_data;
    int              error_detected;
    DWORD            result;

    result = snprintf(search_path, sizeof(search_path) - 1, "%s\\*", path);

    if (result <= 0) {
        return CIO_ERROR;
    }

    find_file_handle = FindFirstFileA(search_path, &find_file_data);

    if (find_file_handle == INVALID_HANDLE_VALUE) {
        return CIO_ERROR;
    }

    target_file_flags = FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE;
    error_detected = CIO_FALSE;
    result = 0;

    do {
        if (strcmp(find_file_data.cFileName, ".")  != 0 &&
            strcmp(find_file_data.cFileName, "..") != 0) {

            result = snprintf(entry_path, sizeof(entry_path) - 1, "%s\\%s", path,
                              find_file_data.cFileName);

            if (result > 0) {
                if (find_file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (current_depth < depth_limit) {
                        result = (DWORD) cio_utils_recursive_delete_handler(entry_path,
                                                                            current_depth + 1,
                                                                            depth_limit);

                        if (result != CIO_OK) {
                            error_detected = CIO_TRUE;
                        }
                    }
                    else {
                        error_detected = CIO_TRUE;
                    }
                }
                else if (find_file_data.dwFileAttributes & target_file_flags) {
                    result = DeleteFileA(entry_path);

                    if (result == 0) {
                        error_detected = CIO_TRUE;
                    }
                }

            }
            else {
                error_detected = CIO_TRUE;
            }
        }

        if (error_detected == CIO_FALSE) {
            result = FindNextFile(find_file_handle, &find_file_data);

            if (result == 0) {
                result = GetLastError();

                if (result != ERROR_NO_MORE_FILES) {
                    error_detected = CIO_TRUE;
                }

                break;
            }
        }
    }
    while (error_detected == CIO_FALSE);

    FindClose(find_file_handle);

    if (error_detected) {
        return CIO_ERROR;
    }

    result = RemoveDirectoryA(path);

    if (result == 0) {
        return CIO_ERROR;
    }

    return CIO_OK;
}

int cio_utils_recursive_delete(const char *dir)
{
    DWORD result;

    result = cio_utils_recursive_delete_handler(dir, 0, 100);

    if (result != CIO_OK) {
        return -1;
    }

    return 0;
}
#endif

int cio_utils_read_file(const char *path, char **buf, size_t *size)
{
    int ret;
    char *data;
    FILE *fp;
    struct stat st;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }

    ret = fstat(fileno(fp), &st);
    if (ret == -1) {
        fclose(fp);
        perror("fstat");
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        fclose(fp);
        return -1;
    }

    data = calloc(st.st_size, 1);
    if (!data) {
        perror("calloc");
        fclose(fp);
        return -1;
    }

    ret = fread(data, st.st_size, 1, fp);
    if (ret != 1) {
        free(data);
        fclose(fp);
        return -1;
    }
    fclose(fp);

    *buf = data;
    *size = st.st_size;

    return 0;
}

#ifdef CIO_HAVE_GETPAGESIZE
int cio_getpagesize()
{
    return getpagesize();
}
#endif
