// Copyright (C) 2022 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_CFG_ROUTING_HPP_
#define VSOMEIP_V3_CFG_ROUTING_HPP_

#include <boost/asio/ip/address.hpp>

#include <vsomeip/internal/logger.hpp>
#include <vsomeip/primitive_types.hpp>

#ifdef ANDROID
#include "internal_android.hpp"
#else
#include "internal.hpp"
#endif

namespace vsomeip_v3 {
namespace cfg {

struct routing_host_t {
    std::string name_;
    boost::asio::ip::address unicast_;
    port_t port_;

    routing_host_t() : port_(VSOMEIP_ROUTING_HOST_PORT_DEFAULT) {}

    routing_host_t &operator=(const routing_host_t &_other) {
        name_ = _other.name_;
        unicast_ = _other.unicast_;
        port_ = _other.port_;

        return *this;
    }
};

struct routing_guests_t {
    boost::asio::ip::address unicast_;
    std::map<std::pair<uid_t, gid_t>,
        std::set<std::pair<port_t, port_t> >
    > ports_;

    routing_guests_t &operator=(const routing_guests_t &_other) {
        unicast_ = _other.unicast_;
        ports_ = _other.ports_;

        return *this;
    }
};

struct routing_t {
    bool is_enabled_;

    routing_host_t host_;
    routing_guests_t guests_;

    routing_t() : is_enabled_(true) {}

    routing_t &operator=(const routing_t &_other) {
        is_enabled_ = _other.is_enabled_;
        host_ = _other.host_;
        guests_ = _other.guests_;

        return *this;
    }
};

} // namespace cfg
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_CFG_ROUTING_HPP_
