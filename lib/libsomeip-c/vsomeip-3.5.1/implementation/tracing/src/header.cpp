// Copyright (C) 2016-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <cstring>

#include "../include/header.hpp"
#include "../../endpoints/include/endpoint.hpp"
#include "../../endpoints/include/client_endpoint.hpp"
#include "../../utility/include/bithelper.hpp"

namespace vsomeip_v3 {
namespace trace {

bool header::prepare(const std::shared_ptr<endpoint> &_endpoint,
        bool _is_sending, instance_t _instance) {
    return prepare(_endpoint.get(), _is_sending, _instance);
}

bool header::prepare(const endpoint *_endpoint, bool _is_sending,
        instance_t _instance) {
    boost::asio::ip::address its_address;
    unsigned short its_port(0);
    protocol_e its_protocol(protocol_e::unknown);

    if (_endpoint) {
        const client_endpoint* its_client_endpoint =
                dynamic_cast<const client_endpoint*>(_endpoint);
        if (its_client_endpoint) {

            its_client_endpoint->get_remote_address(its_address);
            if (its_address.is_v6()) {
                return false;
            }

            its_port = its_client_endpoint->get_remote_port();

            if (_endpoint->is_local()) {
                its_protocol = protocol_e::local;
            } else {
                if (_endpoint->is_reliable()) {
                    its_protocol = protocol_e::tcp;
                } else {
                    its_protocol = protocol_e::udp;
                }
            }
        }
    }
    prepare(its_address.to_v4(), its_port, its_protocol, _is_sending, _instance);
    return true;
}

void header::prepare(const boost::asio::ip::address_v4 &_address,
        std::uint16_t _port, protocol_e _protocol,
        bool _is_sending, instance_t _instance) {

    bithelper::write_uint32_be((uint32_t)_address.to_ulong(), data_);   // [0-3] Address
    bithelper::write_uint16_be(_port, &data_[4]);                       // [4-5] Port
    data_[6] = static_cast<byte_t>(_protocol);                          //   [6] Protocol
    data_[7] = static_cast<byte_t>(_is_sending);                        //   [7] is_sending
    bithelper::write_uint16_be(_instance, &data_[8]);                   // [8-9] Instance
}

} // namespace trace
} // namespace vsomeip_v3
