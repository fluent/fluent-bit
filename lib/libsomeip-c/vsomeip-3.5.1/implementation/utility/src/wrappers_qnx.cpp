// Copyright (C) 2020-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifdef __QNX__

#include <sys/socket.h>
#include <sys/types.h>

#include <fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dcmd_ip.h>
#include <sys/netmgr.h>
#include <sys/sockmsg.h>
#include <unistd.h>

typedef enum accept_msg_t {
	ACCEPT1=1,
	ACCEPT4,
} accept_msg_t;

struct _io_sock_accept {
	struct _io_openfd msg;
	accept_msg_t type;
	int flags;
	socklen_t anamelen;
};

typedef union {
	struct _io_sock_accept i;
}   io_sock_accept_t;

static int
__accept (int s, struct sockaddr *addr, socklen_t *addrlen, accept_msg_t msg_type, int flags)
{
	/* This is basically _sopenfd specifying a return buffer for dst address */
	int fd2;
	int ret, niov;
	io_sock_accept_t msg;
	struct _io_openfd *open;
	struct _server_info info;
	iov_t iov[2];
	socklen_t len;

	if ((addrlen) && (*addrlen > 0) && (!addr)) {
		/* Prevent addr dereference */
		errno = EINVAL;
		return -1;
	}

	if (s == -1 || ConnectServerInfo(0, s, &info) != s) {
		errno = EBADF;
		return -1;
	}

	fd2 = ConnectAttach(info.nd, info.pid, info.chid, 0, _NTO_COF_CLOEXEC | _NTO_COF_INSECURE);
	if (fd2 == -1) {
		return -1;
	}

	open = &msg.i.msg;
	memset(open, 0x00, sizeof *open);
	open->type = _IO_OPENFD;
	open->combine_len = sizeof open;
	open->ioflag = 0;
	open->sflag = 0;
	open->xtype = _IO_OPENFD_ACCEPT;
	open->info.pid = getpid();
	open->info.chid = info.chid;
	open->info.scoid = info.scoid;
	open->info.coid = s;

	msg.i.type = msg_type;
	msg.i.flags = flags;
	if (addr && addrlen && (*addrlen > 0)) {
		/* Only send len > 0 if addr is set (accept1() assumption) */
		len = *addrlen;
	} else {
		len = 0;
	}
	msg.i.anamelen = len;

	niov = 0;
	SETIOV(iov + niov, &msg.i, sizeof(msg.i));
	niov++;

	if (len > 0) {
		/* Only send buffer space required */
		SETIOV(iov + niov, addr, len);
		niov++;
	}

	ret = MsgSendv(fd2, iov, niov, iov, niov);
	if (ret == -1) {
		if(errno == ENOSYS) {
			errno = ENOTSOCK;
		}
		ConnectDetach(fd2);
		return -1;
	}

	if (addr && addrlen && (*addrlen > 0)) {
		*addrlen = msg.i.anamelen;
	}

	ConnectFlags_r(0, fd2, FD_CLOEXEC, (flags & SOCK_CLOEXEC) ? 1 : 0);

	return fd2;
}

int
accept4 (int s, struct sockaddr *addr, socklen_t *addrlen, int flags) {
	return __accept(s, addr, addrlen, ACCEPT4, flags);
}

/*
 * These definitions MUST remain in the global namespace.
 */
extern "C"
{
    /*
     * The real socket(2), renamed by GCC.
     */
    int __real_socket(int domain, int type, int protocol) noexcept;

    /*
     * Overrides socket(2) to set SOCK_CLOEXEC by default.
     */
    int __wrap_socket(int domain, int type, int protocol) noexcept
    {
        return __real_socket(domain, type | SOCK_CLOEXEC, protocol);
    }

    /*
     * Overrides accept(2) to set SOCK_CLOEXEC by default.
     */
    int __wrap_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
    {
        return accept4(sockfd, addr, addrlen, SOCK_CLOEXEC);
    }

    /*
     * The real open(2), renamed by GCC.
     */
    int __real_open(const char *pathname, int flags, mode_t mode);

    /*
     * Overrides open(2) to set O_CLOEXEC by default.
     */
    int __wrap_open(const char *pathname, int flags, mode_t mode)
    {
        return __real_open(pathname, flags | O_CLOEXEC, mode);
    }
}

#endif
