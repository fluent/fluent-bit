// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_UDP_CLIENT_ENDPOINT_IMPL_HPP_
#define VSOMEIP_V3_UDP_CLIENT_ENDPOINT_IMPL_HPP_

#include <memory>

#include <boost/asio/strand.hpp>
#include <boost/asio/ip/udp.hpp>

#include <vsomeip/defines.hpp>

#include "client_endpoint_impl.hpp"
#include "tp_reassembler.hpp"

namespace vsomeip_v3 {

class endpoint_adapter;

typedef client_endpoint_impl<
            boost::asio::ip::udp
        > udp_client_endpoint_base_impl;

class udp_client_endpoint_impl: virtual public udp_client_endpoint_base_impl {

public:
    udp_client_endpoint_impl(const std::shared_ptr<endpoint_host>& _endpoint_host,
                             const std::shared_ptr<routing_host>& _routing_host,
                             const endpoint_type& _local,
                             const endpoint_type& _remote,
                             boost::asio::io_context &_io,
                             const std::shared_ptr<configuration>& _configuration);
    virtual ~udp_client_endpoint_impl();

    void start();
    void restart(bool _force);

    void receive_cbk(boost::system::error_code const &_error,
                     std::size_t _bytes, const message_buffer_ptr_t& _recv_buffer);

    std::uint16_t get_local_port() const;
    void set_local_port(port_t _port);

    bool get_remote_address(boost::asio::ip::address &_address) const;
    std::uint16_t get_remote_port() const;
    bool is_local() const;

    void print_status();
    bool is_reliable() const;

    void send_cbk(boost::system::error_code const &_error,
                          std::size_t _bytes, const message_buffer_ptr_t &_sent_msg);
private:
    void send_queued(std::pair<message_buffer_ptr_t, uint32_t> &_entry);
    void get_configured_times_from_endpoint(
            service_t _service, method_t _method,
            std::chrono::nanoseconds *_debouncing,
            std::chrono::nanoseconds *_maximum_retention) const;
    void connect();
    void receive();
    void set_local_port();
    std::string get_address_port_remote() const;
    std::string get_address_port_local() const;
    std::string get_remote_information() const;
    bool tp_segmentation_enabled(
            service_t _service,
            instance_t _instance,
            method_t _method) const;
    std::uint32_t get_max_allowed_reconnects() const;
    void max_allowed_reconnects_reached();

private:
    const boost::asio::ip::address remote_address_;
    const std::uint16_t remote_port_;
    const int udp_receive_buffer_size_;
    std::shared_ptr<tp::tp_reassembler> tp_reassembler_;

    std::mutex last_sent_mutex_;
    std::chrono::steady_clock::time_point last_sent_;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_UDP_CLIENT_ENDPOINT_IMPL_HPP_
