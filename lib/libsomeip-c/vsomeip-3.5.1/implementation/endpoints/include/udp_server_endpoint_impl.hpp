// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_UDP_SERVER_ENDPOINT_IMPL_HPP_
#define VSOMEIP_V3_UDP_SERVER_ENDPOINT_IMPL_HPP_

#include <boost/asio/ip/udp.hpp>
#include <vsomeip/defines.hpp>

#include "server_endpoint_impl.hpp"
#include "tp_reassembler.hpp"

namespace vsomeip_v3 {
typedef server_endpoint_impl<
            boost::asio::ip::udp
        > udp_server_endpoint_base_impl;

// callback type to sent messages (SD)
using on_unicast_sent_cbk_t =
        std::function<void(const byte_t*, length_t, const boost::asio::ip::address&)>;
// callback type to own multicast messages received
using on_sent_multicast_received_cbk_t =
        std::function<void(const byte_t*, length_t, const boost::asio::ip::address&)>;

class udp_server_endpoint_impl: public udp_server_endpoint_base_impl {

public:
    udp_server_endpoint_impl(const std::shared_ptr<endpoint_host>& _endpoint_host,
                             const std::shared_ptr<routing_host>& _routing_host,
                             boost::asio::io_context &_io,
                             const std::shared_ptr<configuration>& _configuration);
    virtual ~udp_server_endpoint_impl() = default;

    void init(const endpoint_type& _local, boost::system::error_code& _error);
    void start();
    void stop();

    void receive();

    bool send_to(const std::shared_ptr<endpoint_definition> _target,
            const byte_t *_data, uint32_t _size);
    bool send_error(const std::shared_ptr<endpoint_definition> _target,
                const byte_t *_data, uint32_t _size);
    bool send_queued(const target_data_iterator_type _it);
    void get_configured_times_from_endpoint(
            service_t _service, method_t _method,
            std::chrono::nanoseconds *_debouncing,
            std::chrono::nanoseconds *_maximum_retention) const;

    VSOMEIP_EXPORT void join(const std::string &_address);
    VSOMEIP_EXPORT void join_unlocked(const std::string &_address);
    VSOMEIP_EXPORT void leave(const std::string &_address);
    VSOMEIP_EXPORT void set_multicast_option(const boost::asio::ip::address &_address,
                                             bool _is_join, boost::system::error_code& _error);

    void add_default_target(service_t _service,
            const std::string &_address, uint16_t _port);
    void remove_default_target(service_t _service);
    bool get_default_target(service_t _service, endpoint_type &_target) const;

    std::uint16_t get_local_port() const;
    void set_local_port(uint16_t _port);
    bool is_local() const;

    void print_status();
    bool is_reliable() const;

    // Callback to sent messages
    void set_unicast_sent_callback(const on_unicast_sent_cbk_t& _cbk);
    // to own multicast messages received
    void set_sent_multicast_received_callback(const on_sent_multicast_received_cbk_t& _cbk);
    void set_receive_own_multicast_messages(bool value);

    bool is_joining() const;

private:
    void leave_unlocked(const std::string &_address);
    void set_broadcast();
    void receive_unicast();
    void receive_multicast(uint8_t _id);
    bool is_joined(const std::string &_address) const;
    bool is_joined(const std::string &_address, bool& _received) const;
    std::string get_remote_information(
            const target_data_iterator_type _it) const;
    std::string get_remote_information(const endpoint_type& _remote) const;

    std::string get_address_port_local() const;
    bool tp_segmentation_enabled(
            service_t _service,
            instance_t _instance,
            method_t _method) const;

    void on_unicast_received(boost::system::error_code const &_error,
            std::size_t _bytes);

    void on_multicast_received(boost::system::error_code const &_error,
            std::size_t _bytes, uint8_t _multicast_id,
			const boost::asio::ip::address &_destination);

    void on_message_received(boost::system::error_code const &_error,
                     std::size_t _bytes,
                     bool _is_multicast,
                     endpoint_type const &_remote,
                     message_buffer_t const &_buffer);

    bool is_same_subnet(const boost::asio::ip::address &_address) const;

    void shutdown_and_close();
    void unicast_shutdown_and_close_unlocked();
    void multicast_shutdown_and_close_unlocked();

private:
    std::shared_ptr<socket_type> unicast_socket_;
    endpoint_type unicast_remote_;
    message_buffer_t unicast_recv_buffer_;
    mutable std::mutex unicast_mutex_;

    bool is_v4_;

    std::shared_ptr<socket_type> multicast_socket_;
    std::unique_ptr<endpoint_type> multicast_local_;
    endpoint_type multicast_remote_;
    message_buffer_t multicast_recv_buffer_;
    mutable std::recursive_mutex multicast_mutex_;
    uint8_t multicast_id_;
    std::map<std::string, bool> joined_;
    std::atomic<bool> joined_group_;

    mutable std::mutex default_targets_mutex_;
    std::map<service_t, endpoint_type> default_targets_;

    boost::asio::ip::address netmask_;
    unsigned short prefix_;

    std::uint16_t local_port_;

    std::shared_ptr<tp::tp_reassembler> tp_reassembler_;
    boost::asio::steady_timer tp_cleanup_timer_;

    std::mutex last_sent_mutex_;
    std::chrono::steady_clock::time_point last_sent_;

    std::atomic<bool> is_stopped_;

    // to tracking sent messages
    on_unicast_sent_cbk_t on_unicast_sent_;

    // to receive own multicast messages
    bool receive_own_multicast_messages_;
    on_sent_multicast_received_cbk_t on_sent_multicast_received_;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_UDP_SERVER_ENDPOINT_IMPL_HPP_
