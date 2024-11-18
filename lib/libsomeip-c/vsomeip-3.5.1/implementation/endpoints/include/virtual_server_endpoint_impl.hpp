// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_VIRTUAL_SERVER_ENDPOINT_IMPL_HPP_
#define VSOMEIP_V3_VIRTUAL_SERVER_ENDPOINT_IMPL_HPP_

#include <boost/asio/io_context.hpp>
#include <vsomeip/primitive_types.hpp>
#include "../include/endpoint.hpp"

namespace vsomeip_v3 {

class virtual_server_endpoint_impl : public endpoint, public std::enable_shared_from_this<virtual_server_endpoint_impl> {
public:
    virtual_server_endpoint_impl(
            const std::string &_address,
            uint16_t _port,
            bool _reliable,
            boost::asio::io_context &_io);

    virtual ~virtual_server_endpoint_impl();

    void start();
    void prepare_stop(const endpoint::prepare_stop_handler_t &_handler,
                      service_t _service);
    void stop();

    bool is_established() const;
    bool is_established_or_connected() const;
    void set_established(bool _established);
    void set_connected(bool _connected);

    bool send(const byte_t *_data, uint32_t _size);
    bool send_to(const std::shared_ptr<endpoint_definition> _target,
            const byte_t *_data, uint32_t _size);
    bool send_error(const std::shared_ptr<endpoint_definition> _target,
            const byte_t *_data, uint32_t _size);
    void enable_magic_cookies();
    void receive();

    void add_default_target(service_t _service,
            const std::string &_address, uint16_t _port);
    void remove_default_target(service_t _service);
    void remove_stop_handler(service_t _service);

    bool get_remote_address(boost::asio::ip::address &_address) const;
    std::uint16_t get_local_port() const;
    void set_local_port(uint16_t _port);
    std::uint16_t get_remote_port() const;
    bool is_reliable() const;
    bool is_local() const;

    void restart(bool _force);

    void register_error_handler(const error_handler_t &_handler);
    void print_status();

    size_t get_queue_size() const;

private:
    std::string address_;
    uint16_t port_;
    bool reliable_;

    boost::asio::io_context &io_;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_VIRTUAL_SERVER_ENDPOINT_IMPL_HPP_
