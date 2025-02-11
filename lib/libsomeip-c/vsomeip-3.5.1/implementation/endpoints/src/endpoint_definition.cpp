// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/constants.hpp>

#include "../include/endpoint_definition.hpp"

namespace vsomeip_v3 {

std::map<std::tuple<service_t, instance_t, boost::asio::ip::address, uint16_t, bool>,
         std::shared_ptr<endpoint_definition> > endpoint_definition::definitions_;

std::mutex endpoint_definition::definitions_mutex_;

std::shared_ptr<endpoint_definition>
endpoint_definition::get(const boost::asio::ip::address &_address,
                         uint16_t _port, bool _is_reliable, service_t _service, instance_t _instance) {
    auto key = std::make_tuple(_service, _instance, _address, _port, _is_reliable);
    std::lock_guard<std::mutex> its_lock(definitions_mutex_);
    std::shared_ptr<endpoint_definition> its_result;

    auto found_endpoint = definitions_.find(key);
    if (found_endpoint != definitions_.end()) {
        its_result = found_endpoint->second;
    }

    if (!its_result) {
            its_result = std::make_shared<endpoint_definition>(
                             _address, _port, _is_reliable);
            definitions_[key] = its_result;
    }

    return its_result;
}

endpoint_definition::endpoint_definition(
        const boost::asio::ip::address &_address, uint16_t _port,
        bool _is_reliable)
        : address_(_address), port_(_port), remote_port_(_port),
          is_reliable_(_is_reliable) {
}

const boost::asio::ip::address & endpoint_definition::get_address() const {
    return address_;
}

uint16_t endpoint_definition::get_port() const {
    return port_;
}

bool endpoint_definition::is_reliable() const {
    return is_reliable_;
}

uint16_t endpoint_definition::get_remote_port() const {
    return remote_port_;
}

void endpoint_definition::set_remote_port(uint16_t _port) {
    remote_port_ = _port;
}


} // namespace vsomeip_v3
