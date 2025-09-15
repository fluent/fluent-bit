/*
 * Copyright (C) 2023 Amazon Inc.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_common.h"
#include "win_util.h"

// From 1601-01-01 to 1970-01-01 there are 134774 days.
static const uint64_t NT_to_UNIX_epoch_in_ns =
    134774ull * 86400ull * 1000ull * 1000ull * 1000ull;

__wasi_timestamp_t
convert_filetime_to_wasi_timestamp(LPFILETIME filetime)
{
    ULARGE_INTEGER temp = { .HighPart = filetime->dwHighDateTime,
                            .LowPart = filetime->dwLowDateTime };

    // WASI timestamps are measured in nanoseconds whereas FILETIME structs are
    // represented in terms 100-nanosecond intervals.
    return (temp.QuadPart * 100ull) - NT_to_UNIX_epoch_in_ns;
}

FILETIME
convert_wasi_timestamp_to_filetime(__wasi_timestamp_t timestamp)
{
    ULARGE_INTEGER temp = { .QuadPart =
                                (timestamp + NT_to_UNIX_epoch_in_ns) / 100ull };

    FILETIME ret = { .dwLowDateTime = temp.LowPart,
                     .dwHighDateTime = temp.HighPart };

    return ret;
}

__wasi_errno_t
convert_windows_error_code(DWORD windows_error_code)
{
    switch (windows_error_code) {
        case ERROR_INVALID_PARAMETER:
        case ERROR_INVALID_HANDLE:
        case ERROR_NEGATIVE_SEEK:
            return __WASI_EINVAL;
        case ERROR_SHARING_VIOLATION:
        case ERROR_PIPE_BUSY:
            return __WASI_EBUSY;
        case ERROR_ACCESS_DENIED:
            return __WASI_EACCES;
        case ERROR_ALREADY_EXISTS:
        case ERROR_FILE_EXISTS:
            return __WASI_EEXIST;
        case ERROR_NO_MORE_FILES:
        case ERROR_FILE_NOT_FOUND:
        case ERROR_INVALID_NAME:
            return __WASI_ENOENT;
        case ERROR_PRIVILEGE_NOT_HELD:
            return __WASI_EPERM;
        case ERROR_NOT_ENOUGH_MEMORY:
            return __WASI_ENOMEM;
        case ERROR_NOACCESS:
            return __WASI_EFAULT;
        case ERROR_DIR_NOT_EMPTY:
            return __WASI_ENOTEMPTY;
        case ERROR_DIRECTORY:
            return __WASI_ENOTDIR;
        case ERROR_IO_PENDING:
        case ERROR_INSUFFICIENT_BUFFER:
        case ERROR_INVALID_FLAGS:
        case ERROR_NO_UNICODE_TRANSLATION:
        default:
            return __WASI_EINVAL;
    }
}

#ifdef UWP_DEFAULT_VPRINTF
int
uwp_print_to_debugger(const char *format, va_list ap)
{
    // Provide a stack buffer which should be large enough for any realistic
    // string so we avoid making an allocation on every printf call.
    char stack_buf[2048];
    char *buf = stack_buf;
    int ret = vsnprintf(stack_buf, sizeof(stack_buf), format, ap);

    if ((size_t)ret >= sizeof(stack_buf)) {
        // Allocate an extra byte for the null terminator.
        char *heap_buf = BH_MALLOC((unsigned int)(ret) + 1);
        buf = heap_buf;

        if (heap_buf == NULL) {
            // Output as much as we can to the debugger if allocating a buffer
            // fails.
            OutputDebugStringA(stack_buf);
            return ret;
        }

        ret = vsnprintf(heap_buf, (size_t)ret + 1, format, ap);
    }

    if (ret >= 0)
        OutputDebugStringA(buf);

    if (buf != stack_buf)
        BH_FREE(buf);

    return ret;
}
#endif

__wasi_errno_t
convert_winsock_error_code(int error_code)
{
    switch (error_code) {
        case WSASYSNOTREADY:
        case WSAEWOULDBLOCK:
            return __WASI_EAGAIN;
        case WSAVERNOTSUPPORTED:
            return __WASI_ENOTSUP;
        case WSAEINPROGRESS:
            return __WASI_EINPROGRESS;
        case WSAEPROCLIM:
            return __WASI_EBUSY;
        case WSAEFAULT:
            return __WASI_EFAULT;
        case WSAENETDOWN:
            return __WASI_ENETDOWN;
        case WSAENOTSOCK:
            return __WASI_ENOTSOCK;
        case WSAEINTR:
            return __WASI_EINTR;
        case WSAEAFNOSUPPORT:
            return __WASI_EAFNOSUPPORT;
        case WSAEMFILE:
            return __WASI_ENFILE;
        case WSAEINVAL:
            return __WASI_EINVAL;
        case WSAENOBUFS:
            return __WASI_ENOBUFS;
        case WSAEPROTONOSUPPORT:
            return __WASI_EPROTONOSUPPORT;
        case WSAEPROTOTYPE:
            return __WASI_EPROTOTYPE;
        case WSAESOCKTNOSUPPORT:
            return __WASI_ENOTSUP;
        case WSAECONNABORTED:
            return __WASI_ECONNABORTED;
        case WSAECONNRESET:
            return __WASI_ECONNRESET;
        case WSAENOTCONN:
            return __WASI_ENOTCONN;
        case WSAEINVALIDPROCTABLE:
        case WSAEINVALIDPROVIDER:
        case WSAEPROVIDERFAILEDINIT:
        case WSANOTINITIALISED:
        default:
            return __WASI_EINVAL;
    }
}
