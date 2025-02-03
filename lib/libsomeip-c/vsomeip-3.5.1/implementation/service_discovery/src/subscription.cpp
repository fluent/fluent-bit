// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/subscription.hpp"

#include <vsomeip/internal/logger.hpp>

namespace vsomeip_v3 {
namespace sd {

major_version_t subscription::get_major() const {
    return major_;
}

void subscription::set_major(major_version_t _major) {
    major_ = _major;
}

ttl_t subscription::get_ttl() const {
    return ttl_;
}

void subscription::set_ttl(ttl_t _ttl) {
    ttl_ = _ttl;
}

std::shared_ptr<endpoint> subscription::get_endpoint(bool _reliable) const {
    return _reliable ? reliable_ : unreliable_;
}

void subscription::set_endpoint(const std::shared_ptr<endpoint>& _endpoint,
        bool _reliable) {
    if (_reliable)
        reliable_ = _endpoint;
    else
        unreliable_ = _endpoint;
}

bool subscription::is_selective() const {
    return is_selective_;
}
void subscription::set_selective(const bool _is_selective) {
    is_selective_ = _is_selective;
}

subscription_state_e
subscription::get_state(const client_t _client) const {
    std::lock_guard<std::mutex> its_lock(clients_mutex_);
    auto found_client = clients_.find(_client);
    if (found_client != clients_.end())
        return found_client->second;
    return subscription_state_e::ST_UNKNOWN;
}

void
subscription::set_state(
        const client_t _client, const subscription_state_e _state) {
    std::lock_guard<std::mutex> its_lock(clients_mutex_);
    auto found_client = clients_.find(_client);
    if (found_client != clients_.end())
        found_client->second = _state;
}

bool subscription::is_tcp_connection_established() const {
    return tcp_connection_established_;
}
void subscription::set_tcp_connection_established(bool _is_established) {
    tcp_connection_established_ = _is_established;
}

bool subscription::is_udp_connection_established() const {
    return udp_connection_established_;
}
void subscription::set_udp_connection_established(bool _is_established) {
    udp_connection_established_ = _is_established;
}

bool
subscription::add_client(const client_t _client) {
    std::lock_guard<std::mutex> its_lock(clients_mutex_);
    auto find_client = clients_.find(_client);
    if (find_client != clients_.end())
        return false;

    clients_[_client] = subscription_state_e::ST_UNKNOWN;
    return true;
}

bool
subscription::remove_client(const client_t _client) {
    std::lock_guard<std::mutex> its_lock(clients_mutex_);
    auto its_size = clients_.size();
    clients_.erase(_client);
    return its_size > clients_.size();
}

std::set<client_t> subscription::get_clients() const {
    std::set<client_t> its_clients;
    {
        std::lock_guard<std::mutex> its_lock(clients_mutex_);
        for (const auto its_item : clients_)
            its_clients.insert(its_item.first);
    }
    return its_clients;
}

bool subscription::has_client() const {
    std::lock_guard<std::mutex> its_lock(clients_mutex_);
    return (clients_.size() > 0);
}

bool subscription::has_client(const client_t _client) const {
    std::lock_guard<std::mutex> its_lock(clients_mutex_);
    return clients_.find(_client) != clients_.end();
}

void subscription::set_eventgroupinfo(
        const std::shared_ptr<eventgroupinfo> _info) {
    eg_info_ = _info;
}
std::weak_ptr<eventgroupinfo> subscription::get_eventgroupinfo() const {
    return eg_info_;
}

} // namespace sd
} // namespace vsomeip_v3
