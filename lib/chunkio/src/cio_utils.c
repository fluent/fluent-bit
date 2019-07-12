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

#include <chunkio/chunkio_compat.h>
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
int cio_utils_recursive_delete(const char *dir)
{
    return -1;
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
