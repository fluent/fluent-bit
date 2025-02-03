// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_TCP_CLIENT_ENDPOINT_IMPL_HPP_
#define VSOMEIP_V3_TCP_CLIENT_ENDPOINT_IMPL_HPP_

#include <chrono>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>

#include <vsomeip/defines.hpp>
#include "client_endpoint_impl.hpp"
#if defined(__QNX__)
#include "../../utility/include/qnx_helper.hpp"
#endif

namespace vsomeip_v3 {

typedef client_endpoint_impl<
            boost::asio::ip::tcp
        > tcp_client_endpoint_base_impl;

class tcp_client_endpoint_impl: public tcp_client_endpoint_base_impl {
public:
    tcp_client_endpoint_impl(const std::shared_ptr<endpoint_host>& _endpoint_host,
                             const std::shared_ptr<routing_host>& _routing_host,
                             const endpoint_type& _local,
                             const endpoint_type& _remote,
                             boost::asio::io_context &_io,
                             const std::shared_ptr<configuration>& _configuration);
    virtual ~tcp_client_endpoint_impl();

    void init();
    void start();
    void restart(bool _force);

    std::uint16_t get_local_port() const;
    void set_local_port(port_t _port);

    bool get_remote_address(boost::asio::ip::address &_address) const;
    std::uint16_t get_remote_port() const;
    bool is_reliable() const;
    bool is_local() const;
    void print_status();

    void send_cbk(boost::system::error_code const &_error, std::size_t _bytes,
                  const message_buffer_ptr_t& _sent_msg);
private:
    void send_queued(std::pair<message_buffer_ptr_t, uint32_t> &_entry);
    void get_configured_times_from_endpoint(
            service_t _service, method_t _method,
            std::chrono::nanoseconds *_debouncing,
            std::chrono::nanoseconds *_maximum_retention) const;
    bool is_magic_cookie(const message_buffer_ptr_t& _recv_buffer,
                         size_t _offset) const;
    void send_magic_cookie(message_buffer_ptr_t &_buffer);

    void receive_cbk(boost::system::error_code const &_error,
                     std::size_t _bytes,
                     const message_buffer_ptr_t&  _recv_buffer,
                     std::size_t _recv_buffer_size);

    void connect();
    void receive();
    void receive(message_buffer_ptr_t  _recv_buffer,
                 std::size_t _recv_buffer_size,
                 std::size_t _missing_capacity);
    void calculate_shrink_count(const message_buffer_ptr_t& _recv_buffer,
                                std::size_t _recv_buffer_size);
    std::string get_address_port_remote() const;
    std::string get_address_port_local() const;
    void handle_recv_buffer_exception(const std::exception &_e,
                                      const message_buffer_ptr_t& _recv_buffer,
                                      std::size_t _recv_buffer_size);
    void set_local_port();
    std::size_t write_completion_condition(
            const boost::system::error_code& _error,
            std::size_t _bytes_transferred, std::size_t _bytes_to_send,
            service_t _service, method_t _method, client_t _client, session_t _session,
            const std::chrono::steady_clock::time_point _start);
    std::string get_remote_information() const;
    std::shared_ptr<struct timing> get_timing(
            const service_t& _service, const instance_t& _instance) const;
    std::uint32_t get_max_allowed_reconnects() const;
    void max_allowed_reconnects_reached();

    void wait_until_sent(const boost::system::error_code &_error);

    const std::uint32_t recv_buffer_size_initial_;
    message_buffer_ptr_t recv_buffer_;
    std::uint32_t shrink_count_;
    const std::uint32_t buffer_shrink_threshold_;

    const boost::asio::ip::address remote_address_;
    const std::uint16_t remote_port_;
    std::chrono::steady_clock::time_point last_cookie_sent_;
    const std::chrono::milliseconds send_timeout_;
    const std::chrono::milliseconds send_timeout_warning_;

    std::uint32_t tcp_restart_aborts_max_;
    std::uint32_t tcp_connect_time_max_;
    std::atomic<uint32_t> aborted_restart_count_;
    std::chrono::steady_clock::time_point connect_timepoint_;

    boost::asio::steady_timer sent_timer_;

};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_TCP_CLIENT_ENDPOINT_IMPL_HPP_
