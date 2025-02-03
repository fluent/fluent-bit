// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#if defined(__linux__) || defined(ANDROID)

#include <cerrno>
#include <cstring>
#include <sys/socket.h>

#include "../include/credentials.hpp"

#include <vsomeip/internal/logger.hpp>
#ifdef ANDROID
#include "../../configuration/include/internal_android.hpp"
#else
#include "../../configuration/include/internal.hpp"
#endif

namespace vsomeip_v3 {

void credentials::activate_credentials(const int _fd) {
    int optval = 1;
    if (setsockopt(_fd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
        VSOMEIP_ERROR << __func__ << ": vSomeIP Security: Activating socket option for receiving "
                      << "credentials failed.";
    }
}

void credentials::deactivate_credentials(const int _fd) {
    int optval = 0;
    if (setsockopt(_fd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
        VSOMEIP_ERROR << __func__ << ": vSomeIP Security: Deactivating socket option for receiving "
                      << "credentials failed.";
    }
}

boost::optional<credentials::received_t> credentials::receive_credentials(const int _fd) {
    struct msghdr msgh;
    struct iovec iov[2];
    union {
        struct cmsghdr cmh;
        char   control[CMSG_SPACE(sizeof(struct ucred))];
    } control_un;

    // We don't need address of peer as we using connect
    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;

    // Set fields of 'msgh' to point to buffer used to receive (real) data read by recvmsg()
    msgh.msg_iov = iov;
    msgh.msg_iovlen = 2;

    // Set 'msgh' fields to describe 'control_un'
    msgh.msg_control = control_un.control;
    msgh.msg_controllen = sizeof(control_un.control);

    // Sender client_id and client_host_length will be received as data
    client_t client = VSOMEIP_ROUTING_CLIENT;
    uint8_t client_host_length(0);
    iov[0].iov_base = &client;
    iov[0].iov_len = sizeof(client_t);
    iov[1].iov_base = &client_host_length;
    iov[1].iov_len = sizeof(uint8_t);

    // Set 'control_un' to describe ancillary data that we want to receive
    control_un.cmh.cmsg_len = CMSG_LEN(sizeof(struct ucred));
    control_un.cmh.cmsg_level = SOL_SOCKET;
    control_un.cmh.cmsg_type = SCM_CREDENTIALS;

    // Receive client_id plus client_host_length plus ancillary data
    ssize_t nr = recvmsg(_fd, &msgh, 0);
    if (nr == -1) {
        VSOMEIP_ERROR << __func__ << ": vSomeIP Security: Receiving credentials failed. No data. errno: " << std::strerror(errno);
        return boost::none;
    }

    struct cmsghdr* cmhp = CMSG_FIRSTHDR(&msgh);
    if (cmhp == NULL || cmhp->cmsg_len != CMSG_LEN(sizeof(struct ucred))
            || cmhp->cmsg_level != SOL_SOCKET || cmhp->cmsg_type != SCM_CREDENTIALS) {
        VSOMEIP_ERROR << __func__ << ": vSomeIP Security: Receiving credentials failed. Invalid data.";
        return boost::none;
    }

    // Use the implicitly-defined copy constructor
    struct ucred ucred = *reinterpret_cast<struct ucred*>(CMSG_DATA(cmhp));

    msgh.msg_iov = iov;
    msgh.msg_iovlen = 1;
    msgh.msg_control = nullptr;
    msgh.msg_controllen = 0;

    // Receive client_host as data
    std::string client_host(client_host_length, '\0');
    iov[0].iov_base = &client_host.front();
    iov[0].iov_len = client_host.length();

    nr = recvmsg(_fd, &msgh, 0);
    if (nr == -1) {
        VSOMEIP_ERROR << __func__ << ": vSomeIP Security: Receiving client host failed. No data. errno: " << std::strerror(errno);
        return boost::none;
    }

    return received_t{client, ucred.uid, ucred.gid, client_host};
}

void credentials::send_credentials(const int _fd, client_t _client, std::string _client_host) {
    struct msghdr msgh;
    struct iovec iov[3];
    auto client_host_length = static_cast<uint8_t>(_client_host.length());

    // data to send
    msgh.msg_iov = &iov[0];
    msgh.msg_iovlen = 3;
    iov[0].iov_base = &_client;
    iov[0].iov_len = sizeof(client_t);
    iov[1].iov_base = &client_host_length;
    iov[1].iov_len = sizeof(uint8_t);
    iov[2].iov_base = &_client_host[0];
    iov[2].iov_len = client_host_length;

    // destination not needed as we use connect
    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;

    // credentials not need to set explicitly
    msgh.msg_control = NULL;
    msgh.msg_controllen = 0;

    // send client id with credentials
    ssize_t ns = sendmsg(_fd, &msgh, 0);
    if (ns == -1) {
        VSOMEIP_ERROR << __func__ << ": vSomeIP Security: Sending credentials failed. errno: " << std::strerror(errno);
    }
}

} // namespace vsomeip_v3

#endif // __linux__ || ANDROID
