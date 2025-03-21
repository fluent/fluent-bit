#ifndef _WINUIO_H
#define _WINUIO_H

#include <inttypes.h>

#ifndef _WIN32
#include <unistd.h>
#else
#include <errno.h>
#include <io.h>
#include <BaseTsd.h>
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SSIZE_T ssize_t;
#endif

struct mk_iovec
{
    void   *iov_base;    /* Base address of a memory region for input or output */
    size_t  iov_len;     /* The size of the memory pointed to by iov_base */
};

/* Long way to go here, it's mostly a placeholder */

static inline ssize_t readv(int fildes, const struct mk_iovec *iov, int iovcnt)
{
    errno = ENOSYS;
    return -1;
}

static inline ssize_t writev(int fildes, const struct mk_iovec *iov, int iovcnt)
{
    int i;
    uint32_t bytes_written = 0;

    for (i = 0; i < iovcnt; i++) {
        int len;

        len = send((SOCKET)fildes, iov[i].iov_base, (int)iov[i].iov_len, 0);
        if (len == SOCKET_ERROR) {
                uint32_t err = GetLastError();
            // errno = win_to_posix_error(err);
            bytes_written = -1;
            break;
        }
        bytes_written += len;
    }

    return bytes_written;
}


#endif /* _WINUIO_H */

