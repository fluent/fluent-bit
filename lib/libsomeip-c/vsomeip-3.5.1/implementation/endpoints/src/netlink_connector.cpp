// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#if defined(__linux__) || defined(ANDROID)

#include <thread>

#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include<sstream>

#include <vsomeip/internal/logger.hpp>

#include "../include/netlink_connector.hpp"

namespace vsomeip_v3 {

void netlink_connector::register_net_if_changes_handler(const net_if_changed_handler_t& _handler) {
    handler_ = _handler;
}

void netlink_connector::unregister_net_if_changes_handler() {
    handler_ = nullptr;
}

void netlink_connector::stop() {
    std::lock_guard<std::mutex> its_lock(socket_mutex_);
    boost::system::error_code its_error;
    socket_.shutdown(socket_.shutdown_both, its_error);
    socket_.close(its_error);
    if (its_error) {
        VSOMEIP_WARNING << "Error closing NETLINK socket!";
    }
}

void netlink_connector::start() {
    std::lock_guard<std::mutex> its_lock(socket_mutex_);
    boost::system::error_code ec;
    if (socket_.is_open()) {
        socket_.close(ec);
        if (ec) {
            VSOMEIP_WARNING << "Error closing NETLINK socket: " << ec.message();
        }
    }
    socket_.open(nl_protocol(NETLINK_ROUTE), ec);
    if (ec) {
        VSOMEIP_WARNING << "Error opening NETLINK socket: " << ec.message();
        if (handler_) {
            handler_(true, "n/a", true);
            handler_(false, "n/a", true);
        }
        return;
    }
    if (socket_.is_open()) {
        socket_.bind(nl_endpoint<nl_protocol>(
                RTMGRP_LINK |
                RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR |
                RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE |
                RTMGRP_IPV4_MROUTE | RTMGRP_IPV6_MROUTE), ec);

        if (ec && ec != boost::asio::error::address_in_use) {
            VSOMEIP_WARNING << "Error binding NETLINK socket: " << ec.message();
            if (handler_) {
                handler_(true, "n/a", true);
                handler_(false, "n/a", true);
            }

            return;
        }

        send_ifa_request();

        socket_.async_receive(
            boost::asio::buffer(&recv_buffer_[0], recv_buffer_size),
            std::bind(
                &netlink_connector::receive_cbk,
                shared_from_this(),
                std::placeholders::_1,
                std::placeholders::_2
            )
        );
    } else {
        VSOMEIP_WARNING << "Error opening NETLINK socket!";
        if (handler_) {
            handler_(true, "n/a", true);
            handler_(false, "n/a", true);
        }
    }
}

void netlink_connector::receive_cbk(boost::system::error_code const &_error,
                 std::size_t _bytes) {
    if (!_error) {
        size_t len = _bytes;

        unsigned int address(0);
        if (address_.is_v4()) {
            inet_pton(AF_INET, address_.to_string().c_str(), &address);
        } else {
            inet_pton(AF_INET6, address_.to_string().c_str(), &address);
        }

        struct nlmsghdr *nlh = (struct nlmsghdr *)&recv_buffer_[0];

        while ((NLMSG_OK(nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE)) {
            char ifname[IF_NAMESIZE];
            switch (nlh->nlmsg_type) {
                case RTM_NEWADDR: {
                    // New Address information
                    struct ifaddrmsg *ifa = (ifaddrmsg *)NLMSG_DATA(nlh);
                    if (has_address(ifa, IFA_PAYLOAD(nlh), address)) {
                        net_if_index_for_address_ = static_cast<int>(ifa->ifa_index);
                        auto its_if = net_if_flags_.find(static_cast<int>(ifa->ifa_index));
                        if (its_if != net_if_flags_.end()) {
                            if ((its_if->second & IFF_UP) &&
                                    (is_requiring_link_ ? (its_if->second & IFF_RUNNING) : true)) {
                                if (handler_) {
                                    if_indextoname(ifa->ifa_index,ifname);
                                    handler_(true, ifname, true);
                                    send_rt_request();
                                }
                            } else {
                                if (handler_) {
                                    if_indextoname(ifa->ifa_index,ifname);
                                    handler_(true, ifname, false);
                                }
                            }
                        } else {
                            // Request interface information
                            // as we don't know about up/running state!
                           send_ifi_request();
                        }
                    }
                    break;
                }
                case RTM_NEWLINK: {
                    // New Interface information
                    struct ifinfomsg *ifi = (ifinfomsg *)NLMSG_DATA(nlh);
                    net_if_flags_[ifi->ifi_index] = ifi->ifi_flags;
                    if (net_if_index_for_address_ == ifi->ifi_index) {
                        if ((ifi->ifi_flags & IFF_UP) &&
                            (is_requiring_link_ ? (ifi->ifi_flags & IFF_RUNNING) : true)) {
                            if (handler_) {
                                if_indextoname(static_cast<unsigned int>(ifi->ifi_index),ifname);
                                handler_(true, ifname, true);
                                send_rt_request();
                            }
                        } else {
                            if (handler_) {
                                if_indextoname(static_cast<unsigned int>(ifi->ifi_index),ifname);
                                handler_(true, ifname, false);
                            }
                        }
                    }
                    break;
                }
                case RTM_NEWROUTE: {
                    struct rtmsg *routemsg = (rtmsg *)NLMSG_DATA(nlh);
                    std::string its_route_name;
                    if (check_sd_multicast_route_match(routemsg, RTM_PAYLOAD(nlh),
                            &its_route_name)) {
                        if (handler_) {
                            handler_(false, its_route_name, true);
                        }
                    }
                    break;
                }
                case RTM_DELROUTE: {
                    struct rtmsg *routemsg = (rtmsg *)NLMSG_DATA(nlh);
                    std::string its_route_name;
                    if (check_sd_multicast_route_match(routemsg, RTM_PAYLOAD(nlh),
                            &its_route_name)) {
                        if (handler_) {
                            handler_(false, its_route_name, false);
                        }
                    }
                    break;
                }
                case NLMSG_ERROR: {
                    struct nlmsgerr *errmsg = (nlmsgerr *)NLMSG_DATA(nlh);
                    if (errmsg->error != 0) {
                        handle_netlink_error(errmsg);
                    }
                    break;
                }
                case NLMSG_DONE:
                case NLMSG_NOOP:
                default:
                    break;
            }
            nlh = NLMSG_NEXT(nlh, len);
        }
        {
            std::lock_guard<std::mutex> its_lock(socket_mutex_);
            if (socket_.is_open()) {
                socket_.async_receive(
                    boost::asio::buffer(&recv_buffer_[0], recv_buffer_size),
                    std::bind(
                        &netlink_connector::receive_cbk,
                        shared_from_this(),
                        std::placeholders::_1,
                        std::placeholders::_2
                    )
                );
            }
        }
    } else {
        if (_error != boost::asio::error::operation_aborted) {
            VSOMEIP_WARNING << "Error receive_cbk NETLINK socket!" << _error.message();
            boost::system::error_code its_error;
            {
                std::lock_guard<std::mutex> its_lock(socket_mutex_);
                if (socket_.is_open()) {
                    socket_.shutdown(socket_.shutdown_both, its_error);
                    socket_.close(its_error);
                    if (its_error) {
                        VSOMEIP_WARNING << "Error closing NETLINK socket!"
                                << its_error.message();
                    }
                }
            }
            if (handler_) {
                handler_(true, "n/a", true);
                handler_(false, "n/a", true);
            }
        }
    }
}

void netlink_connector::send_cbk(boost::system::error_code const &_error, std::size_t _bytes) {
    (void)_bytes;
    if (_error) {
        VSOMEIP_WARNING << "Netlink send error : " << _error.message();
        if (handler_) {
            handler_(true, "n/a", true);
            handler_(false, "n/a", true);
        }
    }
}

void netlink_connector::send_ifa_request(std::uint32_t _retry) {
    typedef struct {
        struct nlmsghdr nlhdr;
        struct ifaddrmsg addrmsg;
    } netlink_address_msg;
    netlink_address_msg get_address_msg;
    memset(&get_address_msg, 0, sizeof(get_address_msg));
    get_address_msg.nlhdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    get_address_msg.nlhdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
    get_address_msg.nlhdr.nlmsg_type = RTM_GETADDR;
    // the sequence number has stored the request sequence and the retry count.
    // request sequece is stored in the LSB (least significant byte) and
    // retry is stored in the 2nd LSB.
    get_address_msg.nlhdr.nlmsg_seq = ifa_request_sequence_ | (_retry << retry_bit_shift_);
    if (address_.is_v4()) {
        get_address_msg.addrmsg.ifa_family = AF_INET;
    } else {
        get_address_msg.addrmsg.ifa_family = AF_INET6;
    }

    socket_.async_send(
        boost::asio::buffer(&get_address_msg, get_address_msg.nlhdr.nlmsg_len),
        std::bind(
            &netlink_connector::send_cbk,
            shared_from_this(),
            std::placeholders::_1,
            std::placeholders::_2
        )
    );
}

void netlink_connector::send_ifi_request(std::uint32_t _retry) {
    typedef struct {
        struct nlmsghdr nlhdr;
        struct ifinfomsg infomsg;
    } netlink_link_msg;
    netlink_link_msg get_link_msg;
    memset(&get_link_msg, 0, sizeof(get_link_msg));
    get_link_msg.nlhdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    get_link_msg.nlhdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
    get_link_msg.nlhdr.nlmsg_type = RTM_GETLINK;
    get_link_msg.infomsg.ifi_family = AF_UNSPEC;
    // the sequence number has stored the request sequence and the retry count.
    // request sequece is stored in the LSB (least significant byte) and
    // retry is stored in the 2nd LSB.
    get_link_msg.nlhdr.nlmsg_seq = ifi_request_sequence_ | (_retry << retry_bit_shift_);

    {
        std::lock_guard<std::mutex> its_lock(socket_mutex_);
        socket_.async_send(
            boost::asio::buffer(&get_link_msg, get_link_msg.nlhdr.nlmsg_len),
            std::bind(
                &netlink_connector::send_cbk,
                shared_from_this(),
                std::placeholders::_1,
                std::placeholders::_2
            )
        );
    }
}

void netlink_connector::send_rt_request(std::uint32_t _retry) {
    typedef struct {
        struct nlmsghdr nlhdr;
        struct rtgenmsg routemsg;
    } netlink_route_msg;

    netlink_route_msg get_route_msg;
    memset(&get_route_msg, 0, sizeof(get_route_msg));
    get_route_msg.nlhdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    get_route_msg.nlhdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    get_route_msg.nlhdr.nlmsg_type = RTM_GETROUTE;
    // the sequence number has stored the request sequence and the retry count.
    // request sequece is stored in the LSB (least significant byte) and
    // retry is stored in the 2nd LSB.
    get_route_msg.nlhdr.nlmsg_seq = rt_request_sequence_ | (_retry << retry_bit_shift_);
    if (multicast_address_.is_v6()) {
        get_route_msg.routemsg.rtgen_family = AF_INET6;
    } else {
        get_route_msg.routemsg.rtgen_family = AF_INET;
    }

    {
        std::lock_guard<std::mutex> its_lock(socket_mutex_);
        socket_.async_send(
            boost::asio::buffer(&get_route_msg, get_route_msg.nlhdr.nlmsg_len),
            std::bind(
                &netlink_connector::send_cbk,
                shared_from_this(),
                std::placeholders::_1,
                std::placeholders::_2
            )
        );
    }
}

void netlink_connector::handle_netlink_error(struct nlmsgerr *_error_msg) {
    // the sequence number has stored the request sequence and the retry count.
    // retry is stored in the 2nd LSB.
    std::uint32_t retry = _error_msg->msg.nlmsg_seq >> retry_bit_shift_;
    if (retry >= max_retries_) {
        VSOMEIP_ERROR << "netlink_connector::receive_cbk received "
            "error message: " << strerror(-_error_msg->error)
            << " type " << std::dec << _error_msg->msg.nlmsg_type
            << " seq " << _error_msg->msg.nlmsg_seq;
        return;
    }

    // the sequence number has stored the request sequence and the retry count.
    // request sequece is stored in the LSB.
    std::uint32_t request_sequence = _error_msg->msg.nlmsg_seq & request_sequence_bitmask_;
    std::string request_type{};
    if (_error_msg->msg.nlmsg_type == RTM_GETADDR && request_sequence == ifa_request_sequence_) {
        request_type = "address request";
        send_ifa_request(retry + 1);
    } else if (_error_msg->msg.nlmsg_type == RTM_GETLINK && request_sequence == ifi_request_sequence_) {
        request_type = "link request";
        send_ifi_request(retry + 1);
    } else if (_error_msg->msg.nlmsg_type == RTM_GETROUTE && request_sequence == rt_request_sequence_) {
        request_type = "route request";
        send_rt_request(retry + 1);
    }

    if (!request_type.empty()) {
        VSOMEIP_INFO << "Retrying netlink " << request_type;
    }
}

bool netlink_connector::has_address(struct ifaddrmsg * ifa_struct,
        size_t length,
        const unsigned int address) {

    struct rtattr *retrta;
    retrta = static_cast<struct rtattr *>(IFA_RTA(ifa_struct));
    while RTA_OK(retrta, length) {
        if (retrta->rta_type == IFA_ADDRESS) {
            char pradd[128];
            unsigned int * tmp_address = (unsigned int *)RTA_DATA(retrta);
            if (address_.is_v4()) {
                inet_ntop(AF_INET, tmp_address, pradd, sizeof(pradd));
            } else {
                inet_ntop(AF_INET6, tmp_address, pradd, sizeof(pradd));
            }
            if (address == *tmp_address) {
                return true;
            }
        }
        retrta = RTA_NEXT(retrta, length);
    }

    return false;
}

bool netlink_connector::check_sd_multicast_route_match(struct rtmsg* _routemsg,
                                              size_t _length,
                                              std::string* _routename) const {
    struct rtattr *retrta;
    retrta = static_cast<struct rtattr *>(RTM_RTA(_routemsg));
    int if_index(0);
    char if_name[IF_NAMESIZE] = "n/a";
    char address[INET6_ADDRSTRLEN] = "n/a";
    char gateway[INET6_ADDRSTRLEN] = "n/a";
    bool matches_sd_multicast(false);
    while (RTA_OK(retrta, _length)) {
        if (retrta->rta_type == RTA_DST) {
            // check if added/removed route matches on configured SD multicast address
            size_t rtattr_length = RTA_PAYLOAD(retrta);
            if (rtattr_length == 4 && multicast_address_.is_v4()) { // IPv4 route
                inet_ntop(AF_INET, RTA_DATA(retrta), address, sizeof(address));
                std::uint32_t netmask(0);
                for (int i = 31; i > 31 - _routemsg->rtm_dst_len; i--) {
                    netmask |= static_cast<std::uint32_t>(1 << i);
                }
                const std::uint32_t dst_addr = ntohl(*((std::uint32_t *)RTA_DATA(retrta)));
                const std::uint32_t dst_net = (dst_addr & netmask);
                const std::uint32_t sd_addr = static_cast<std::uint32_t>(multicast_address_.to_v4().to_ulong());
                const std::uint32_t sd_net = (sd_addr & netmask);
                matches_sd_multicast = !(dst_net ^ sd_net);
            } else if (rtattr_length == 16 && multicast_address_.is_v6()) { // IPv6 route
                inet_ntop(AF_INET6, RTA_DATA(retrta), address, sizeof(address));
                std::uint32_t netmask2[4] = {0,0,0,0};
                for (int i = 127; i > 127 - _routemsg->rtm_dst_len; i--) {
                    if (i > 95) {
                        netmask2[0] |= static_cast<std::uint32_t>(1 << (i-96));
                    } else if (i > 63) {
                        netmask2[1] |= static_cast<std::uint32_t>(1 << (i-64));
                    } else if (i > 31) {
                        netmask2[2] |= static_cast<std::uint32_t>(1 << (i-32));
                    } else {
                        netmask2[3] |= static_cast<std::uint32_t>(1 << i);
                    }
                }

                for (int i = 0; i < 4; i++) {
#ifndef ANDROID
                    const std::uint32_t dst = ntohl((*(struct in6_addr*)RTA_DATA(retrta)).__in6_u.__u6_addr32[i]);
#else
                    const std::uint32_t dst = ntohl((*(struct in6_addr*)RTA_DATA(retrta)).in6_u.u6_addr32[i]);
#endif
                    const std::uint32_t sd = ntohl(reinterpret_cast<std::uint32_t*>(multicast_address_.to_v6().to_bytes().data())[i]);
                    const std::uint32_t dst_net = dst & netmask2[i];
                    const std::uint32_t sd_net = sd & netmask2[i];
                    matches_sd_multicast = !(dst_net ^ sd_net);
                    if (!matches_sd_multicast) {
                        break;
                    }
                }
            }
        } else if (retrta->rta_type == RTA_OIF) {
            if_index = *(int *)(RTA_DATA(retrta));
            if_indextoname(static_cast<unsigned int>(if_index),if_name);
        } else if (retrta->rta_type == RTA_GATEWAY) {
            size_t rtattr_length = RTA_PAYLOAD(retrta);
            if (rtattr_length == 4) {
                inet_ntop(AF_INET, RTA_DATA(retrta), gateway, sizeof(gateway));
            } else if (rtattr_length == 16) {
                inet_ntop(AF_INET6, RTA_DATA(retrta), gateway, sizeof(gateway));
            }
        }
        retrta = RTA_NEXT(retrta, _length);
    }
    if (matches_sd_multicast && net_if_index_for_address_ == if_index) {
        std::stringstream stream;
        stream << address << "/" <<  (static_cast<uint32_t>(_routemsg->rtm_dst_len))
                << " if: " << if_name << " gw: " << gateway;
        *_routename = stream.str();
        return true;
    } else if (if_index > 0 && net_if_index_for_address_ == if_index &&
            _routemsg->rtm_dst_len == 0) {
        // the default route is set to the interface on which the SD will listen
        // therefore no explicit multicast route is required.
        std::stringstream stream;
        stream << "default route (0.0.0.0/0) if: " << if_name << " gw: " << gateway;
        *_routename = stream.str();
        return true;
    }
    return false;
}

} // namespace vsomeip_v3

#endif // __linux__ or ANDROID
