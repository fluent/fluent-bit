// Copyright (C) 2018-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <cstring>

#include "../include/selective_option_impl.hpp"
#include "../../message/include/deserializer.hpp"
#include "../../message/include/serializer.hpp"

namespace vsomeip_v3 {
namespace sd {

selective_option_impl::selective_option_impl() {
    length_ = 1; // always contains "Reserved"
    type_ = option_type_e::SELECTIVE;
}

selective_option_impl::~selective_option_impl() {
}

bool
selective_option_impl::equals(const option_impl &_other) const {
    bool is_equal(option_impl::equals(_other));
    if (is_equal) {
        const selective_option_impl &its_other
            = dynamic_cast<const selective_option_impl &>(_other);
        is_equal = (clients_ == its_other.clients_);
    }
    return is_equal;
}

std::set<client_t> selective_option_impl::get_clients() const {
    std::set<client_t> its_clients(clients_);
    return its_clients;
}

void selective_option_impl::set_clients(const std::set<client_t> &_clients) {
    clients_ = _clients;
    length_ = uint16_t(1 + clients_.size() * sizeof(client_t));
}

bool selective_option_impl::add_client(client_t _client) {
    auto its_result = clients_.insert(_client);
    length_ = uint16_t(1 + clients_.size() * sizeof(client_t));
    return its_result.second;
}

bool selective_option_impl::remove_client(client_t _client) {
    auto its_size = clients_.size();
    clients_.erase(_client);
    length_ = uint16_t(1 + clients_.size() * sizeof(client_t));
    return (clients_.size() < its_size);
}

bool selective_option_impl::has_clients() const {
    return !clients_.empty();
}

bool selective_option_impl::has_client(client_t _client) {
    auto find_client = clients_.find(_client);
    return (find_client != clients_.end());
}

bool selective_option_impl::serialize(vsomeip_v3::serializer *_to) const {
    bool is_successful = option_impl::serialize(_to);
    if (is_successful) {
        for (auto &its_client : clients_)
            _to->serialize(its_client);
    }
    return is_successful;
}

bool selective_option_impl::deserialize(vsomeip_v3::deserializer *_from) {
    bool is_successful = option_impl::deserialize(_from);
    if (is_successful) {
        uint16_t i = 1;
        while (i < length_) {
            client_t its_client;
            is_successful = _from->deserialize(its_client);

            clients_.insert(its_client);
            i = uint16_t(i + sizeof(client_t));
        }
    }
    return is_successful;
}

} // namespace sd
} // namespace vsomeip_v3
