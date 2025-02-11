// Copyright (C) 2020-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_LOCAL_SERVER_ENDPOINT_IMPL_RECEIVE_OP_HPP_
#define VSOMEIP_V3_LOCAL_SERVER_ENDPOINT_IMPL_RECEIVE_OP_HPP_

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)

#include <boost/asio/local/stream_protocol.hpp>
#include <memory>

namespace vsomeip_v3 {
namespace local_endpoint_receive_op {

typedef boost::asio::local::stream_protocol::socket socket_type_t;
typedef std::function<
    void (boost::system::error_code const &_error, size_t _size,
          const std::uint32_t &, const std::uint32_t &)> receive_handler_t;

struct storage :
    public std::enable_shared_from_this<storage>
{
    socket_type_t &socket_;
    receive_handler_t handler_;
    byte_t *buffer_ = nullptr;
    size_t length_;
    uid_t uid_;
    gid_t gid_;
    size_t bytes_;

    storage(
        socket_type_t &_socket,
        receive_handler_t _handler,
        byte_t *_buffer,
        size_t _length,
        uid_t _uid,
        gid_t _gid,
        size_t _bytes
    ) : socket_(_socket),
        handler_(_handler),
        buffer_(_buffer),
        length_(_length),
        uid_(_uid),
        gid_(_gid),
        bytes_(_bytes)
    {}
};

inline
std::function<void(boost::system::error_code _error)>
receive_cb (std::shared_ptr<storage> _data) {
    return [_data](boost::system::error_code _error) {
        if (!_error) {
            if (!_data->socket_.native_non_blocking())
                _data->socket_.native_non_blocking(true, _error);
            #if defined(__linux__)
            for (;;) {
                ssize_t its_result;
                int its_flags(0);

                // Set buffer
                struct iovec its_vec[1];
                its_vec[0].iov_base = _data->buffer_;
                its_vec[0].iov_len = _data->length_;

                union {
                    struct cmsghdr cmh;
                    char   control[CMSG_SPACE(sizeof(struct ucred))];
                } control_un;

                // Set 'control_un' to describe ancillary data that we want to receive
                control_un.cmh.cmsg_len = CMSG_LEN(sizeof(struct ucred));
                control_un.cmh.cmsg_level = SOL_SOCKET;
                control_un.cmh.cmsg_type = SCM_CREDENTIALS;

                // Build header with all informations to call ::recvmsg
                auto its_header = msghdr();
                its_header.msg_iov = its_vec;
                its_header.msg_iovlen = 1;
                its_header.msg_control = control_un.control;
                its_header.msg_controllen = sizeof(control_un.control);

                // Call recvmsg and handle its result
                errno = 0;
                its_result = ::recvmsg(_data->socket_.native_handle(), &its_header, its_flags);
                _error = boost::system::error_code(its_result < 0 ? errno : 0,
                        boost::asio::error::get_system_category());
                _data->bytes_ += _error ? 0 : static_cast<size_t>(its_result);

                if (_error == boost::asio::error::interrupted)
                    continue;

                if (_error == boost::asio::error::would_block
                        || _error == boost::asio::error::try_again) {
                    _data->socket_.async_wait(socket_type_t::wait_read, receive_cb(_data));
                    return;
                }

                if (_error)
                    break;

                if (_data->bytes_ == 0)
                    _error = boost::asio::error::eof;

                // Extract credentials (UID/GID)
                struct ucred *its_credentials;
                for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&its_header);
                     cmsg != NULL;
                     cmsg = CMSG_NXTHDR(&its_header, cmsg))
                {
                    if (cmsg->cmsg_level == SOL_SOCKET
                        && cmsg->cmsg_type == SCM_CREDENTIALS
                        && cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {

                        its_credentials = (struct ucred *) CMSG_DATA(cmsg);
                        if (its_credentials) {
                            _data->uid_ = its_credentials->uid;
                            _data->gid_ = its_credentials->gid;
                            break;
                        }
                    }
                }

                break;
            }
            #endif
        }

        // Call the handler
        _data->handler_(_error, _data->bytes_, _data->uid_, _data->gid_);
    };
}

} // namespace local_endpoint_receive_op
} // namespace vsomeip

#endif // __linux__ || ANDROID

#endif // VSOMEIP_V3_LOCAL_SERVER_ENDPOINT_IMPL_RECEIVE_OP_HPP_
