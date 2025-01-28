// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_ENDPOINT_HPP_
#define VSOMEIP_V3_ENDPOINT_HPP_

#include <boost/asio/ip/address.hpp>

#include <vsomeip/primitive_types.hpp>
#include <vsomeip/constants.hpp>

#include <vector>

namespace vsomeip_v3 {

class endpoint_definition;

class endpoint {
public:
    typedef std::function<void()> error_handler_t;
    typedef std::function<void(const std::shared_ptr<endpoint> &)> prepare_stop_handler_t;

    virtual ~endpoint() = default;

    virtual void start() = 0;
    virtual void restart(bool _force = false) = 0;
    virtual void stop() = 0;

    virtual void prepare_stop(const prepare_stop_handler_t &_handler,
                              service_t _service = ANY_SERVICE) = 0;

    virtual bool is_established() const = 0;
    virtual bool is_established_or_connected() const = 0;

    virtual bool send(const byte_t *_data, uint32_t _size) = 0;
    virtual bool send_to(const std::shared_ptr<endpoint_definition> _target,
            const byte_t *_data, uint32_t _size) = 0;
    virtual bool send_error(const std::shared_ptr<endpoint_definition> _target,
            const byte_t *_data, uint32_t _size) = 0;
    virtual void enable_magic_cookies() = 0;
    virtual void receive() = 0;

    virtual void add_default_target(service_t _service,
            const std::string &_address, uint16_t _port) = 0;
    virtual void remove_default_target(service_t _service) = 0;
    virtual void remove_stop_handler(service_t _service) = 0;

    virtual std::uint16_t get_local_port() const = 0;
    virtual void set_local_port(uint16_t _port) = 0;
    virtual bool is_reliable() const = 0;
    virtual bool is_local() const = 0;

    virtual void register_error_handler(const error_handler_t &_error) = 0;

    virtual void print_status() = 0;
    virtual size_t get_queue_size() const = 0;

    virtual void set_established(bool _established) = 0;
    virtual void set_connected(bool _connected) = 0;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_ENDPOINT_HPP_
