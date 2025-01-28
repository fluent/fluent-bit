// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_LOCAL_TCP_CLIENT_ENDPOINT_IMPL_HPP_
#define VSOMEIP_V3_LOCAL_TCP_CLIENT_ENDPOINT_IMPL_HPP_

#include <boost/asio/ip/tcp.hpp>

#include <vsomeip/defines.hpp>

#include "client_endpoint_impl.hpp"

namespace vsomeip_v3 {

typedef client_endpoint_impl<
            boost::asio::ip::tcp
        > local_tcp_client_endpoint_base_impl;

class local_tcp_client_endpoint_impl: public local_tcp_client_endpoint_base_impl {
public:
    local_tcp_client_endpoint_impl(const std::shared_ptr<endpoint_host> &_endpoint_host,
                                   const std::shared_ptr<routing_host> &_routing_host,
                                   const endpoint_type &_local,
								   const endpoint_type &_remote,
                                   boost::asio::io_context &_io,
                                   const std::shared_ptr<configuration> &_configuration);
    virtual ~local_tcp_client_endpoint_impl() = default;

    void start();
    void stop();

    bool is_local() const;

    std::uint16_t get_local_port() const;

    void restart(bool _force);
    void print_status();

    bool is_reliable() const;

    // this overrides client_endpoint_impl::send to disable the pull method
    // for local communication
    bool send(const uint8_t *_data, uint32_t _size);
    void get_configured_times_from_endpoint(
            service_t _service, method_t _method,
            std::chrono::nanoseconds *_debouncing,
            std::chrono::nanoseconds *_maximum_retention) const;
private:
    void send_queued(std::pair<message_buffer_ptr_t, uint32_t> &_entry);

    void send_magic_cookie();

    void connect();
    void receive();
    void receive_cbk(boost::system::error_code const &_error,
                     std::size_t _bytes);
    void set_local_port();
    std::string get_remote_information() const;
    bool check_packetizer_space(std::uint32_t _size);
    std::uint32_t get_max_allowed_reconnects() const;
    void max_allowed_reconnects_reached();

    message_buffer_t recv_buffer_;

    // send data
    message_buffer_ptr_t send_data_buffer_;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_LOCAL_TCP_CLIENT_ENDPOINT_IMPL_HPP_
