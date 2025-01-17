// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_ROUTING_HOST_
#define VSOMEIP_V3_ROUTING_HOST_

#include <memory>

#include <boost/asio/ip/address.hpp>

#include <vsomeip/primitive_types.hpp>
#include <vsomeip/vsomeip_sec.h>

#ifdef ANDROID
#include "../../configuration/include/internal_android.hpp"
#else
#include "../../configuration/include/internal.hpp"
#endif // ANDROID

namespace vsomeip_v3 {

class endpoint;

class routing_host {
public:
    virtual ~routing_host() = default;

    virtual void on_message(const byte_t *_data, length_t _length,
                            endpoint *_receiver,
                            bool _is_multicast = false,
                            client_t _bound_client = VSOMEIP_ROUTING_CLIENT,
                            const vsomeip_sec_client_t *_sec_client = nullptr,
                            const boost::asio::ip::address &_remote_address =
                                    boost::asio::ip::address(),
                            std::uint16_t _remote_port = 0) = 0;

    virtual client_t get_client() const = 0;
    virtual void add_known_client(client_t _client, const std::string &_client_host) = 0;

    virtual void remove_subscriptions(port_t _local_port,
            const boost::asio::ip::address &_remote_address,
            port_t _remote_port) = 0;

    virtual routing_state_e get_routing_state() = 0;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_ROUTING_HOST_
