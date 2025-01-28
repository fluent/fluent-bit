// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_UDP_SERVER_ENDPOINT_IMPL_RECEIVE_OP_HPP_
#define VSOMEIP_V3_UDP_SERVER_ENDPOINT_IMPL_RECEIVE_OP_HPP_

#ifdef _WIN32
#include <ws2def.h>
#endif

#include <iomanip>
#include <memory>

#include <boost/asio/ip/udp.hpp>

#include <vsomeip/internal/logger.hpp>

#if defined(__QNX__)
#include <netinet/in.h>
#include <sys/socket.h>
#include "../../utility/include/qnx_helper.hpp"
#endif

namespace vsomeip_v3 {
namespace udp_endpoint_receive_op {

typedef boost::asio::ip::udp::socket socket_type_t;
typedef boost::asio::ip::udp::endpoint endpoint_type_t;
typedef std::function<
    void (boost::system::error_code const &_error, size_t _size,
          std::uint8_t, const boost::asio::ip::address &)> receive_handler_t;

struct storage :
    public std::enable_shared_from_this<storage>
{
    std::recursive_mutex &multicast_mutex_;
    std::weak_ptr<socket_type_t> socket_;
    endpoint_type_t &sender_;
    receive_handler_t handler_;
    byte_t *buffer_ = nullptr;
    size_t length_;
    std::uint8_t multicast_id_;
    bool is_v4_;
    boost::asio::ip::address destination_;
    size_t bytes_;

    storage(
        std::recursive_mutex &_multicast_mutex,
        std::weak_ptr<socket_type_t> _socket,
        endpoint_type_t &_sender,
        receive_handler_t _handler,
        byte_t *_buffer,
        size_t _length,
        std::uint8_t _multicast_id,
        bool _is_v4,
        boost::asio::ip::address _destination,
        size_t _bytes
    ) : multicast_mutex_(_multicast_mutex),
        socket_(_socket),
        sender_(_sender),
        handler_(_handler),
        buffer_(_buffer),
        length_(_length),
        multicast_id_(_multicast_id),
        is_v4_(_is_v4),
        destination_(_destination),
        bytes_(_bytes)
    {}
};

std::function<void(boost::system::error_code _error)>
receive_cb (std::shared_ptr<storage> _data) {
    return [_data](boost::system::error_code _error) {
        _data->sender_ = endpoint_type_t(); // reset

        if (!_error) {

            std::lock_guard<std::recursive_mutex> its_lock(_data->multicast_mutex_);

            auto multicast_socket = _data->socket_.lock();
            if (!multicast_socket) {
                VSOMEIP_WARNING << "udp_endpoint_receive_op::receive_cb: multicast_socket with id " << int{_data->multicast_id_} << " has expired!";
                return;
            }

            if (!multicast_socket->native_non_blocking())
                multicast_socket->native_non_blocking(true, _error);

            for (;;) {
#ifdef _WIN32
                GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;
                LPFN_WSARECVMSG WSARecvMsg;
                DWORD its_bytes;
                SOCKET its_socket { multicast_socket->native_handle() };

                WSAIoctl(its_socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
                    &WSARecvMsg_GUID, sizeof WSARecvMsg_GUID,
                    &WSARecvMsg, sizeof WSARecvMsg,
                    &its_bytes, NULL, NULL);

                int its_result;
                int its_flags { 0 };

                WSABUF its_buf;
                WSAMSG its_msg;

                its_buf.buf = reinterpret_cast<CHAR *>(_data->buffer_);
                its_buf.len = _data->length_;

                its_msg.lpBuffers = &its_buf;
                its_msg.dwBufferCount = 1;
                its_msg.dwFlags = its_flags;

                // Sender & destination address info
                union {
                    struct sockaddr_in v4;
                    struct sockaddr_in6 v6;
                } addr;

                union {
                    struct cmsghdr cmh;
                    union {
                        char   v4[CMSG_SPACE(sizeof(struct in_pktinfo))];
                        char   v6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
                    } control;
                } control_un;

                // Prepare
                if (_data->is_v4_) {
                    its_msg.name = reinterpret_cast<LPSOCKADDR>(&addr);
                    its_msg.namelen = sizeof(sockaddr_in);

                    its_msg.Control.buf = control_un.control.v4;
                    its_msg.Control.len = sizeof(control_un.control.v4);
                } else {
                    its_msg.name = reinterpret_cast<LPSOCKADDR>(&addr);
                    its_msg.namelen = sizeof(sockaddr_in6);

                    its_msg.Control.buf = control_un.control.v6;
                    its_msg.Control.len = sizeof(control_un.control.v6);
                }

                errno = 0;
                its_result = WSARecvMsg(its_socket, &its_msg, &its_bytes,
                    NULL, NULL);

                _error = boost::system::error_code(its_result < 0 ? errno : 0,
                        boost::asio::error::get_system_category());
                _data->bytes_ += _error ? 0 : static_cast<size_t>(its_bytes);

                if (_error == boost::asio::error::interrupted)
                    continue;

                if (_error == boost::asio::error::would_block
                        || _error == boost::asio::error::try_again) {

                    multicast_socket->async_wait(
                        socket_type_t::wait_read,
                        receive_cb(_data)
                    );
                    return;
                }

                if (_error)
                    break;

                if (_data->bytes_ == 0)
                    _error = boost::asio::error::eof;

                // Extract sender & destination addresses
                if (_data->is_v4_) {
                    // sender
                    boost::asio::ip::address_v4 its_sender_address(
                            ntohl(addr.v4.sin_addr.s_addr));
                    std::uint16_t its_sender_port(ntohs(addr.v4.sin_port));
                    _data->sender_ = endpoint_type_t(its_sender_address, its_sender_port);

                    // destination
                    struct in_pktinfo *its_pktinfo_v4;
                    for (struct cmsghdr *cmsg = WSA_CMSG_FIRSTHDR(&its_msg);
                         cmsg != NULL;
                         cmsg = WSA_CMSG_NXTHDR(&its_msg, cmsg)) {

                        if (cmsg->cmsg_level == IPPROTO_IP
                            && cmsg->cmsg_type == IP_PKTINFO
                            && cmsg->cmsg_len == CMSG_LEN(sizeof(*its_pktinfo_v4))) {

                            its_pktinfo_v4 = (struct in_pktinfo*) WSA_CMSG_DATA(cmsg);
                            if (its_pktinfo_v4) {
                                _data->destination_ = boost::asio::ip::address_v4(
                                        ntohl(its_pktinfo_v4->ipi_addr.s_addr));
                                break;
                            }
                        }
                    }
                } else {
                    boost::asio::ip::address_v6::bytes_type its_bytes;

                    // sender
                    boost::asio::ip::address_v6 its_sender_address;
                    for (size_t i = 0; i < its_bytes.size(); i++)
                        its_bytes[i] = addr.v6.sin6_addr.s6_addr[i];
                    std::uint16_t its_sender_port(ntohs(addr.v6.sin6_port));
                    _data->sender_ = endpoint_type_t(its_sender_address, its_sender_port);

                    struct in6_pktinfo *its_pktinfo_v6;
                    for (struct cmsghdr *cmsg = WSA_CMSG_FIRSTHDR(&its_msg);
                         cmsg != NULL;
                         cmsg = CMSG_NXTHDR(&its_msg, cmsg)) {

                        if (cmsg->cmsg_level == IPPROTO_IPV6
                            && cmsg->cmsg_type == IPV6_PKTINFO
                            && cmsg->cmsg_len == WSA_CMSG_LEN(sizeof(*its_pktinfo_v6))) {

                            its_pktinfo_v6 = (struct in6_pktinfo *) WSA_CMSG_DATA(cmsg);
                            if (its_pktinfo_v6) {
                                for (size_t i = 0; i < its_bytes.size(); i++)
                                    its_bytes[i] = its_pktinfo_v6->ipi6_addr.s6_addr[i];
                                _data->destination_ = boost::asio::ip::address_v6(its_bytes);
                                break;
                            }
                        }
                    }
                }

                break;
#else
                ssize_t its_result;
                int its_flags { 0 };

                // Create control elements
                auto its_header = msghdr();
                struct iovec its_vec[1];

                // Prepare
                its_vec[0].iov_base = _data->buffer_;
                its_vec[0].iov_len = _data->length_;

                // Add io buffer
                its_header.msg_iov = its_vec;
                its_header.msg_iovlen = 1;

                // Sender & destination address info
                union {
                    struct sockaddr_in v4;
                    struct sockaddr_in6 v6;
                } addr;

                union {
                    struct cmsghdr cmh;
                    union {
                        char   v4[CMSG_SPACE(sizeof(struct in_pktinfo))];
                        char   v6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
                    } control;
                } control_un;

                // Prepare
                if (_data->is_v4_) {
                    its_header.msg_name = &addr;
                    its_header.msg_namelen = sizeof(sockaddr_in);

                    its_header.msg_control = control_un.control.v4;
                    its_header.msg_controllen = sizeof(control_un.control.v4);
                } else {
                    its_header.msg_name = &addr;
                    its_header.msg_namelen = sizeof(sockaddr_in6);

                    its_header.msg_control = control_un.control.v6;
                    its_header.msg_controllen = sizeof(control_un.control.v6);
                }

                // Call recvmsg and handle its result
                errno = 0;
                its_result = ::recvmsg(multicast_socket->native_handle(), &its_header, its_flags);

                _error = boost::system::error_code(its_result < 0 ? errno : 0,
                        boost::asio::error::get_system_category());
                _data->bytes_ += _error ? 0 : static_cast<size_t>(its_result);

                if (_error == boost::asio::error::interrupted)
                    continue;

                if (_error == boost::asio::error::would_block
                        || _error == boost::asio::error::try_again) {
                    multicast_socket->async_wait(
                        socket_type_t::wait_read,
                        receive_cb(_data)
                    );
                    return;
                }

                if (_error)
                    break;

                if (_data->bytes_ == 0)
                    _error = boost::asio::error::eof;

                // Extract sender & destination addresses
                if (_data->is_v4_) {
                    // sender
                    boost::asio::ip::address_v4 its_sender_address(
                            ntohl(addr.v4.sin_addr.s_addr));
                    in_port_t its_sender_port(ntohs(addr.v4.sin_port));
                    _data->sender_ = endpoint_type_t(its_sender_address, its_sender_port);

                    // destination
                    struct in_pktinfo *its_pktinfo_v4;
                    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&its_header);
                         cmsg != NULL;
                         cmsg = CMSG_NXTHDR(&its_header, cmsg)) {

                        if (cmsg->cmsg_level == IPPROTO_IP
                            && cmsg->cmsg_type == IP_PKTINFO
                            && cmsg->cmsg_len == CMSG_LEN(sizeof(*its_pktinfo_v4))) {

                            its_pktinfo_v4 = (struct in_pktinfo*) CMSG_DATA(cmsg);
                            if (its_pktinfo_v4) {
                                _data->destination_ = boost::asio::ip::address_v4(
                                        ntohl(its_pktinfo_v4->ipi_addr.s_addr));
                                break;
                            }
                        }
                    }
                } else {
                    boost::asio::ip::address_v6::bytes_type its_bytes;

                    // sender
                    for (size_t i = 0; i < its_bytes.size(); i++)
                        its_bytes[i] = addr.v6.sin6_addr.s6_addr[i];
                    boost::asio::ip::address_v6 its_sender_address(its_bytes);
                    in_port_t its_sender_port(ntohs(addr.v6.sin6_port));
                    _data->sender_ = endpoint_type_t(its_sender_address, its_sender_port);

                    struct in6_pktinfo *its_pktinfo_v6;
                    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&its_header);
                         cmsg != NULL;
                         cmsg = CMSG_NXTHDR(&its_header, cmsg)) {

                        if (cmsg->cmsg_level == IPPROTO_IPV6
                            && cmsg->cmsg_type == IPV6_PKTINFO
                            && cmsg->cmsg_len == CMSG_LEN(sizeof(*its_pktinfo_v6))) {

                            its_pktinfo_v6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
                            if (its_pktinfo_v6) {
                                for (size_t i = 0; i < its_bytes.size(); i++)
                                    its_bytes[i] = its_pktinfo_v6->ipi6_addr.s6_addr[i];
                                _data->destination_ = boost::asio::ip::address_v6(its_bytes);
                                break;
                            }
                        }
                    }
                }

                break;
#endif // _WIN32
            }
        }

        // Call the handler
        _data->handler_(_error, _data->bytes_, _data->multicast_id_, _data->destination_);
    };
}

} // namespace udp_endpoint_receive_op
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_UDP_SERVER_ENDPOINT_IMPL_RECEIVE_OP_HPP_
