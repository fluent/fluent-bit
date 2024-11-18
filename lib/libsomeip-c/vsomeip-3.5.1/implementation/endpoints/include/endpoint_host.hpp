// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_ENDPOINT_HOST_HPP_
#define VSOMEIP_V3_ENDPOINT_HOST_HPP_

#include <memory>

#include <boost/asio/ip/address.hpp>

#include <vsomeip/primitive_types.hpp>

#ifdef ANDROID
#include "../../configuration/include/internal_android.hpp"
#else
#include "../../configuration/include/internal.hpp"
#endif

namespace vsomeip_v3 {

class configuration;
class endpoint;

struct multicast_option_t {
    std::shared_ptr<endpoint> endpoint_;
    bool is_join_;
    boost::asio::ip::address address_;
};

class endpoint_host {
public:
    virtual ~endpoint_host() = default;

    virtual void on_connect(std::shared_ptr<endpoint> _endpoint) = 0;
    virtual void on_disconnect(std::shared_ptr<endpoint> _endpoint) = 0;
    virtual bool on_bind_error(std::shared_ptr<endpoint> _endpoint,
            const boost::asio::ip::address &_remote_address,
            uint16_t _remote_port) = 0;
    virtual void on_error(const byte_t *_data, length_t _length,
            endpoint* const _receiver,
            const boost::asio::ip::address &_remote_address,
            std::uint16_t _remote_port) = 0;
    virtual void release_port(uint16_t _port, bool _reliable) = 0;
    virtual client_t get_client() const = 0;
    virtual std::string get_client_host() const = 0;
    virtual instance_t find_instance(service_t _service,
            endpoint * const _endpoint) const = 0;
    virtual void add_multicast_option(const multicast_option_t &_option) = 0;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_ENDPOINT_HOST_HPP_
