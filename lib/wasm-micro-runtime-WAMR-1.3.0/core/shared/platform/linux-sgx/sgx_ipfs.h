/*
 * Copyright (C) 2022 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _LIBC_WASI_SGX_PFS_H
#define _LIBC_WASI_SGX_PFS_H

#include "bh_hashmap.h"

#ifdef __cplusplus
extern "C" {
#endif

int
ipfs_init();
void
ipfs_destroy();
int
ipfs_posix_fallocate(int fd, off_t offset, size_t len);
size_t
ipfs_read(int fd, const struct iovec *iov, int iovcnt, bool has_offset,
          off_t offset);
size_t
ipfs_write(int fd, const struct iovec *iov, int iovcnt, bool has_offset,
           off_t offset);
int
ipfs_close(int fd);
void *
ipfs_fopen(int fd, int flags);
int
ipfs_fflush(int fd);
off_t
ipfs_lseek(int fd, off_t offset, int nwhence);
int
ipfs_ftruncate(int fd, off_t len);

/**
 * Whether two file descriptors are equal.
 */
inline static bool
fd_equal(int left, int right)
{
    return left == right ? true : false;
}

/**
 * Returns the file descriptor as a hash value.
 */
inline static uint32
fd_hash(int fd)
{
    return (uint32)fd;
}

#ifdef __cplusplus
}
#endif

#endif /* end of _LIBC_WASI_SGX_PFS_H */