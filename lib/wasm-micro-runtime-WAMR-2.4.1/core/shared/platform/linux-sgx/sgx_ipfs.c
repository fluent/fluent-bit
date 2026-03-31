/*
 * Copyright (C) 2022 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#if WASM_ENABLE_SGX_IPFS != 0

#include "ssp_config.h"
#include "bh_platform.h"
#include "sgx_ipfs.h"

#include <errno.h>

#include "sgx_tprotected_fs.h"

#define SGX_ERROR_FILE_LOWEST_ERROR_ID SGX_ERROR_FILE_BAD_STATUS
#define SGX_ERROR_FILE_HIGHEST_ERROR_ID SGX_ERROR_FILE_CLOSE_FAILED

// Internal buffer filled with zeroes and used when extending the size of
// protected files.
#define ZEROES_PADDING_LENGTH 32 * 1024
char zeroes_padding[ZEROES_PADDING_LENGTH] = { 0 };

// The mapping between file descriptors and IPFS file pointers.
static HashMap *ipfs_file_list;

// Converts an SGX error code to a POSIX error code.
static __wasi_errno_t
convert_sgx_errno(int error)
{
    if (error >= SGX_ERROR_FILE_LOWEST_ERROR_ID
        && error <= SGX_ERROR_FILE_HIGHEST_ERROR_ID) {
        switch (error) {
            /* The file is in bad status */
            case SGX_ERROR_FILE_BAD_STATUS:
                return ENOTRECOVERABLE;
            /* The Key ID field is all zeros, can't re-generate the encryption
             * key */
            case SGX_ERROR_FILE_NO_KEY_ID:
                return EKEYREJECTED;
            /* The current file name is different then the original file name
             * (not allowed, substitution attack) */
            case SGX_ERROR_FILE_NAME_MISMATCH:
                return EIO;
            /* The file is not an SGX file */
            case SGX_ERROR_FILE_NOT_SGX_FILE:
                return EEXIST;
            /* A recovery file can't be opened, so flush operation can't
             * continue (only used when no EXXX is returned)  */
            case SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE:
                return EIO;
            /* A recovery file can't be written, so flush operation can't
             * continue (only used when no EXXX is returned)  */
            case SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE:
                return EIO;
            /* When opening the file, recovery is needed, but the recovery
             * process failed */
            case SGX_ERROR_FILE_RECOVERY_NEEDED:
                return EIO;
            /* fflush operation (to disk) failed (only used when no EXXX is
             * returned) */
            case SGX_ERROR_FILE_FLUSH_FAILED:
                return EIO;
            /* fclose operation (to disk) failed (only used when no EXXX is
             * returned) */
            case SGX_ERROR_FILE_CLOSE_FAILED:
                return EIO;
        }
    }

    return error;
}

static void *
fd2file(int fd)
{
    return bh_hash_map_find(ipfs_file_list, (void *)(intptr_t)fd);
}

static void
ipfs_file_destroy(void *sgx_file)
{
    sgx_fclose(sgx_file);
}

// Writes a given number of zeroes in file at the current offset.
// The return value is zero if successful; otherwise non-zero.
static int
ipfs_write_zeroes(void *sgx_file, size_t len)
{
    int min_count;

    while (len > 0) {
        min_count = len < ZEROES_PADDING_LENGTH ? len : ZEROES_PADDING_LENGTH;

        if (sgx_fwrite(zeroes_padding, 1, min_count, sgx_file) == 0) {
            errno = convert_sgx_errno(sgx_ferror(sgx_file));
            return -1;
        }

        len -= min_count;
    }

    return 0;
}

int
ipfs_init()
{
    ipfs_file_list =
        bh_hash_map_create(32, true, (HashFunc)fd_hash, (KeyEqualFunc)fd_equal,
                           NULL, (ValueDestroyFunc)ipfs_file_destroy);

    return ipfs_file_list != NULL ? BHT_OK : BHT_ERROR;
}

void
ipfs_destroy()
{
    bh_hash_map_destroy(ipfs_file_list);
}

int
ipfs_posix_fallocate(int fd, off_t offset, size_t len)
{
    void *sgx_file = fd2file(fd);
    if (!sgx_file) {
        return EBADF;
    }

    // The wrapper for fseek takes care of extending the file if sought beyond
    // the end
    if (ipfs_lseek(fd, offset + len, SEEK_SET) == -1) {
        return errno;
    }

    // Make sure the file is allocated by flushing it
    if (sgx_fflush(sgx_file) != 0) {
        return errno;
    }

    return 0;
}

size_t
ipfs_read(int fd, const struct iovec *iov, int iovcnt, bool has_offset,
          off_t offset)
{
    int i;
    off_t original_offset = 0;
    void *sgx_file = fd2file(fd);
    size_t read_result, number_of_read_bytes = 0;

    if (!sgx_file) {
        errno = EBADF;
        return -1;
    }

    if (has_offset) {
        // Save the current offset, to restore it after the read operation
        original_offset = (off_t)sgx_ftell(sgx_file);

        if (original_offset == -1) {
            errno = convert_sgx_errno(sgx_ferror(sgx_file));
            return -1;
        }

        // Move to the desired location
        if (sgx_fseek(sgx_file, offset, SEEK_SET) == -1) {
            errno = convert_sgx_errno(sgx_ferror(sgx_file));
            return -1;
        }
    }

    // For each element in the vector
    for (i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len == 0)
            continue;

        read_result = sgx_fread(iov[i].iov_base, 1, iov[i].iov_len, sgx_file);
        number_of_read_bytes += read_result;

        if (read_result != iov[i].iov_len) {
            if (!sgx_feof(sgx_file)) {
                errno = convert_sgx_errno(sgx_ferror(sgx_file));
                return -1;
            }
        }
    }

    if (has_offset) {
        // Restore the position of the cursor
        if (sgx_fseek(sgx_file, original_offset, SEEK_SET) == -1) {
            errno = convert_sgx_errno(sgx_ferror(sgx_file));
            return -1;
        }
    }

    return number_of_read_bytes;
}

size_t
ipfs_write(int fd, const struct iovec *iov, int iovcnt, bool has_offset,
           off_t offset)
{
    int i;
    off_t original_offset = 0;
    void *sgx_file = fd2file(fd);
    size_t write_result, number_of_written_bytes = 0;

    if (!sgx_file) {
        errno = EBADF;
        return -1;
    }

    if (has_offset) {
        // Save the current offset, to restore it after the read operation
        original_offset = (off_t)sgx_ftell(sgx_file);

        if (original_offset == -1) {
            errno = convert_sgx_errno(sgx_ferror(sgx_file));
            return -1;
        }

        // Move to the desired location
        if (sgx_fseek(sgx_file, offset, SEEK_SET) == -1) {
            errno = convert_sgx_errno(sgx_ferror(sgx_file));
            return -1;
        }
    }

    // For each element in the vector
    for (i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len == 0)
            continue;

        write_result = sgx_fwrite(iov[i].iov_base, 1, iov[i].iov_len, sgx_file);
        number_of_written_bytes += write_result;

        if (write_result != iov[i].iov_len) {
            errno = convert_sgx_errno(sgx_ferror(sgx_file));
            return -1;
        }
    }

    if (has_offset) {
        // Restore the position of the cursor
        if (sgx_fseek(sgx_file, original_offset, SEEK_SET) == -1) {
            errno = convert_sgx_errno(sgx_ferror(sgx_file));
            return -1;
        }
    }

    return number_of_written_bytes;
}

int
ipfs_close(int fd)
{
    void *sgx_file;

    if (!bh_hash_map_remove(ipfs_file_list, (void *)(intptr_t)fd, NULL,
                            &sgx_file)) {
        errno = EBADF;
        return -1;
    }

    if (sgx_fclose(sgx_file)) {
        errno = convert_sgx_errno(sgx_ferror(sgx_file));
        return -1;
    }

    return 0;
}

void *
ipfs_fopen(int fd, int flags)
{
    // Mapping back the mode
    const char *mode;

    bool must_create = (flags & O_CREAT) != 0;
    bool must_truncate = (flags & O_TRUNC) != 0;
    bool must_append = (flags & O_APPEND) != 0;
    bool read_only = (flags & O_ACCMODE) == O_RDONLY;
    bool write_only = (flags & O_ACCMODE) == O_WRONLY;
    bool read_write = (flags & O_ACCMODE) == O_RDWR;

    // The mapping of the mode is similar to the table in the official
    // specifications:
    // https://pubs.opengroup.org/onlinepubs/9699919799/functions/fopen.html
    // Note that POSIX has obtained a file descriptor beforehand.
    // If opened with a destructive mode ("w" or "w+"), the truncate operation
    // already occurred and must not be repeated because this will invalidate
    // the file descriptor obtained by POSIX. Therefore, we do NOT map to the
    // modes that truncate the file ("w" and "w+"). Instead, we map to a
    // non-destructive mode ("r+").

    if (read_only)
        mode = "r";
    else if (write_only && must_create && must_truncate)
        // Rather than "w", we map to a non-destructive mode
        mode = "r+";
    else if (write_only && must_create && must_append)
        mode = "a";
    else if (read_write && must_create && must_append)
        mode = "a+";
    else if (read_write)
        // Rather than "w+", we map to a non-destructive mode
        mode = "r+";
    else
        mode = NULL;

    // Cannot map the requested access to the SGX IPFS
    if (mode == NULL) {
        errno = __WASI_ENOTCAPABLE;
        return NULL;
    }

    // Determine the symbolic link of the file descriptor, because IPFS does not
    // support opening a relative path to a file descriptor (i.e., openat).
    // Using the symbolic link in /proc/self allows to retrieve the same path as
    // opened by the initial openat and respects the chroot of WAMR.
    size_t ret;
    char symbolic_path[32];
    ret =
        snprintf(symbolic_path, sizeof(symbolic_path), "/proc/self/fd/%d", fd);
    if (ret >= sizeof(symbolic_path)) {
        errno = ENAMETOOLONG;
        return NULL;
    }

    // Resolve the symbolic link to real absolute path, because IPFS can only
    // open a file with a same file name it was initially created. Otherwise,
    // IPFS throws SGX_ERROR_FILE_NAME_MISMATCH.
    char real_path[PATH_MAX] = { 0 };
    ret = readlink(symbolic_path, real_path, PATH_MAX - 1);
    if (ret == -1)
        return NULL;

    // Opening the file using the real path
    void *sgx_file = sgx_fopen_auto_key(real_path, mode);

    if (sgx_file == NULL) {
        errno = convert_sgx_errno(sgx_ferror(sgx_file));
        return NULL;
    }

    if (!bh_hash_map_insert(ipfs_file_list, (void *)(intptr_t)fd, sgx_file)) {
        errno = __WASI_ECANCELED;
        sgx_fclose(sgx_file);
        os_printf("An error occurred while inserting the IPFS file pointer in "
                  "the map.\n");
        return NULL;
    }

    return sgx_file;
}

int
ipfs_fflush(int fd)
{
    void *sgx_file = fd2file(fd);

    if (!sgx_file) {
        errno = EBADF;
        return EOF;
    }

    int ret = sgx_fflush(sgx_file);

    if (ret == 1) {
        errno = convert_sgx_errno(sgx_ferror(sgx_file));
        return EOF;
    }

    return ret;
}

off_t
ipfs_lseek(int fd, off_t offset, int nwhence)
{
    off_t cursor_current_location;
    void *sgx_file = fd2file(fd);
    if (!sgx_file) {
        errno = EBADF;
        return -1;
    }

    // Optimization: if the offset is 0 and the whence is SEEK_CUR,
    // this is equivalent of a call to ftell.
    if (offset == 0 && nwhence == SEEK_CUR) {
        cursor_current_location = (off_t)sgx_ftell(sgx_file);

        if (cursor_current_location == -1) {
            errno = convert_sgx_errno(sgx_ferror(sgx_file));
            return -1;
        }

        return cursor_current_location;
    }

    int fseek_result = sgx_fseek(sgx_file, offset, nwhence);

    if (fseek_result == 0) {
        off_t new_offset = (off_t)sgx_ftell(sgx_file);

        if (new_offset == -1) {
            errno = convert_sgx_errno(sgx_ferror(sgx_file));
            return -1;
        }

        return new_offset;
    }
    else {
        // In the case fseek returned an error
        int sgx_error = sgx_ferror(sgx_file);
        if (sgx_error != EINVAL) {
            errno = convert_sgx_errno(sgx_error);
            return -1;
        }

        // We must consider a difference in behavior of sgx_fseek and the POSIX
        // fseek. If the cursor is moved beyond the end of the file, sgx_fseek
        // returns an error, whereas POSIX fseek accepts the cursor move and
        // fill with zeroes the difference for the next write. This
        // implementation handle zeroes completion and moving the cursor forward
        // the end of the file, but does it now (during the fseek), which is
        // different compared to POSIX implementation, that writes zeroes on the
        // next write. This avoids the runtime to keep track of the cursor
        // manually.

        // Assume the error is raised because the cursor is moved beyond the end
        // of the file.

        // If the whence is the current cursor location, retrieve it
        if (nwhence == SEEK_CUR) {
            cursor_current_location = (off_t)sgx_ftell(sgx_file);
        }

        // Move the cursor at the end of the file
        if (sgx_fseek(sgx_file, 0, SEEK_END) == -1) {
            errno = convert_sgx_errno(sgx_ferror(sgx_file));
            return -1;
        }

        // Compute the number of zeroes to append.
        int64_t number_of_zeroes;
        switch (nwhence) {
            case SEEK_SET:
                number_of_zeroes = offset - sgx_ftell(sgx_file);
                break;
            case SEEK_END:
                number_of_zeroes = offset;
                break;
            case SEEK_CUR:
                number_of_zeroes =
                    cursor_current_location + offset - sgx_ftell(sgx_file);
                break;
            default:
                errno = EINVAL;
                return -1;
        }

        // Write the missing zeroes
        if (ipfs_write_zeroes(sgx_file, number_of_zeroes) != 0) {
            return -1;
        }

        // Move again at the end of the file
        if (sgx_fseek(sgx_file, 0, SEEK_END) == -1) {
            errno = convert_sgx_errno(sgx_ferror(sgx_file));
            return -1;
        }

        return offset;
    }
}

// The official API does not provide a way to truncate files.
// Only files extension is supported.
int
ipfs_ftruncate(int fd, off_t len)
{
    void *sgx_file = fd2file(fd);
    if (!sgx_file) {
        errno = EBADF;
        return -1;
    }

    off_t original_offset = sgx_ftell(sgx_file);

    // Optimization path: if the length is smaller than the offset,
    // IPFS does not support truncate to a smaller size.
    if (len < original_offset) {
        os_printf(
            "SGX IPFS does not support truncate files to smaller sizes.\n");
        return __WASI_ECANCELED;
    }

    // Move to the end of the file to determine whether this is
    // a file extension or reduction.
    if (sgx_fseek(sgx_file, 0, SEEK_END) == -1) {
        errno = convert_sgx_errno(sgx_ferror(sgx_file));
        return -1;
    }

    off_t file_size = sgx_ftell(sgx_file);

    // Reducing the file space is not supported by IPFS.
    if (len < file_size) {
        os_printf(
            "SGX IPFS does not support truncate files to smaller sizes.\n");
        return __WASI_ECANCELED;
    }

    // Increasing the size is equal to writing from the end of the file
    // with null bytes.
    if (ipfs_write_zeroes(sgx_file, len - file_size) != 0) {
        return -1;
    }

    // Restore the position of the cursor
    if (sgx_fseek(sgx_file, original_offset, SEEK_SET) == -1) {
        errno = convert_sgx_errno(sgx_ferror(sgx_file));
        return -1;
    }

    return 0;
}

#endif /* end of WASM_ENABLE_SGX_IPFS */
