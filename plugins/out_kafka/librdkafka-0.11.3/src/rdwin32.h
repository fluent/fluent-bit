/*
* librdkafka - Apache Kafka C library
*
* Copyright (c) 2012-2015 Magnus Edenhill
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*/

/**
 * Win32 (Visual Studio) support
 */
#pragma once


#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>
#include <time.h>
#include <assert.h>
#define WIN32_MEAN_AND_LEAN
#include <Winsock2.h>  /* for struct timeval */
#include <io.h>
#include <fcntl.h>


/**
 * Types
 */
typedef SSIZE_T ssize_t;
typedef int socklen_t;

struct iovec {
	void *iov_base;
	size_t iov_len;
};

struct msghdr {
	struct iovec  *msg_iov;
	int            msg_iovlen;
};

#define LOG_EMERG   0
#define LOG_ALERT   1
#define LOG_CRIT    2
#define LOG_ERR     3
#define LOG_WARNING 4
#define LOG_NOTICE  5
#define LOG_INFO    6
#define LOG_DEBUG   7



/**
* Annotations, attributes, optimizers
*/
#ifndef likely
#define likely(x)   x
#endif
#ifndef unlikely
#define unlikely(x) x
#endif

#define RD_UNUSED
#define RD_INLINE  __inline
#define RD_WARN_UNUSED_RESULT
#define RD_NORETURN __declspec(noreturn)
#define RD_IS_CONSTANT(p)  (0)
#define RD_TLS __declspec(thread)


/**
 * Allocation
 */
#define rd_alloca(N) _alloca(N)


/**
 * Strings, formatting, printf, ..
 */

/* size_t and ssize_t format strings */
#define PRIusz  "Iu"
#define PRIdsz  "Id"

#define RD_FORMAT(...)

static RD_UNUSED RD_INLINE
int rd_vsnprintf (char *str, size_t size, const char *format, va_list ap) {
        int cnt = -1;

        if (size != 0)
                cnt = _vsnprintf_s(str, size, _TRUNCATE, format, ap);
        if (cnt == -1)
                cnt = _vscprintf(format, ap);

        return cnt;
}

static RD_UNUSED RD_INLINE
int rd_snprintf (char *str, size_t size, const char *format, ...) {
        int cnt;
        va_list ap;

        va_start(ap, format);
        cnt = rd_vsnprintf(str, size, format, ap);
        va_end(ap);

        return cnt;
}


#define rd_strcasecmp(A,B) _stricmp(A,B)
#define rd_strncasecmp(A,B,N) _strnicmp(A,B,N)


/**
 * Errors
 */
static RD_INLINE RD_UNUSED const char *rd_strerror(int err) {
	static RD_TLS char ret[128];

	strerror_s(ret, sizeof(ret) - 1, err);
	return ret;
}


/**
 * Atomics
 */
#ifndef __cplusplus
#include "rdatomic.h"
#endif


/**
 * Misc
 */

/**
 * Microsecond sleep.
 * 'retry': if true, retry if sleep is interrupted (because of signal)
 */
#define rd_usleep(usec,terminate)  Sleep((usec) / 1000)


/**
 * @brief gettimeofday() for win32
 */
static RD_UNUSED
int rd_gettimeofday (struct timeval *tv, struct timezone *tz) {
	SYSTEMTIME st;
	FILETIME   ft;
	ULARGE_INTEGER d;

	GetSystemTime(&st);
	SystemTimeToFileTime(&st, &ft);
	d.HighPart = ft.dwHighDateTime;
	d.LowPart  = ft.dwLowDateTime;
	tv->tv_sec  = (long)((d.QuadPart - 116444736000000000llu) / 10000000L);
	tv->tv_usec = (long)(st.wMilliseconds * 1000);

	return 0;
}


#define rd_assert(EXPR)  assert(EXPR)


/**
 * Empty struct initializer
 */
#define RD_ZERO_INIT  {0}

#ifndef __cplusplus
/**
 * Sockets, IO
 */

/**
 * @brief Set socket to non-blocking
 * @returns 0 on success or -1 on failure (see rd_kafka_socket_errno)
 */
static RD_UNUSED int rd_fd_set_nonblocking (int fd) {
        int on = 1;
        if (ioctlsocket(fd, FIONBIO, &on) == SOCKET_ERROR)
                return (int)WSAGetLastError();
        return 0;
}

/**
 * @brief Create non-blocking pipe
 * @returns 0 on success or errno on failure
 */
static RD_UNUSED int rd_pipe_nonblocking (int *fds) {
        HANDLE h[2];
        int i;

        if (!CreatePipe(&h[0], &h[1], NULL, 0))
                return (int)GetLastError();
        for (i = 0 ; i < 2 ; i++) {
                DWORD mode = PIPE_NOWAIT;
                /* Set non-blocking */
                if (!SetNamedPipeHandleState(h[i], &mode, NULL, NULL)) {
                        CloseHandle(h[0]);
                        CloseHandle(h[1]);
                        return (int)GetLastError();
                }

                /* Open file descriptor for handle */
                fds[i] = _open_osfhandle((intptr_t)h[i],
                                         i == 0 ?
                                         O_RDONLY | O_BINARY :
                                         O_WRONLY | O_BINARY);

                if (fds[i] == -1) {
                        CloseHandle(h[0]);
                        CloseHandle(h[1]);
                        return (int)GetLastError();
                }
        }
        return 0;
}

#define rd_read(fd,buf,sz) _read(fd,buf,sz)
#define rd_write(fd,buf,sz) _write(fd,buf,sz)
#define rd_close(fd) closesocket(fd)

static RD_UNUSED char *
rd_strerror_w32 (DWORD errcode, char *dst, size_t dstsize) {
        char *t;
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, errcode,
                       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                       (LPSTR)dst, (DWORD)dstsize - 1, NULL);
        /* Remove newlines */
        while ((t = strchr(dst, (int)'\r')) || (t = strchr(dst, (int)'\n')))
                *t = (char)'.';
        return dst;
}

#endif /* !__cplusplus*/
