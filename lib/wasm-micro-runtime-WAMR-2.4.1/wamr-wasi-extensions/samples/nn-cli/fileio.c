/*
 * Copyright (C) 2025 Midokura Japan KK.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

/*
 * modified copy-and-paste from:
 * https://github.com/yamt/toywasm/blob/0eaad8cacd0cc7692946ff19b25994f106113be8/lib/fileio.c
 */

#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "fileio.h"

int
map_file(const char *path, void **pp, size_t *sizep)
{
    void *p;
    size_t size;
    ssize_t ssz;
    int fd;
    int ret;

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        ret = errno;
        assert(ret != 0);
        return ret;
    }
    struct stat st;
    ret = fstat(fd, &st);
    if (ret == -1) {
        ret = errno;
        assert(ret != 0);
        close(fd);
        return ret;
    }
    size = st.st_size;
    if (size > 0) {
        p = malloc(size);
    }
    else {
        /* Avoid a confusing error */
        p = malloc(1);
    }
    if (p == NULL) {
        close(fd);
        return ENOMEM;
    }
    ssz = read(fd, p, size);
    if (ssz != size) {
        ret = errno;
        assert(ret != 0);
        close(fd);
        return ret;
    }
    close(fd);
    *pp = p;
    *sizep = size;
    return 0;
}

void
unmap_file(void *p, size_t sz)
{
    free(p);
}
