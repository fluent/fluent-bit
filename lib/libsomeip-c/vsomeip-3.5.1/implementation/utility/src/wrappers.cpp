// Copyright (C) 2020-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifdef __linux__

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>

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
