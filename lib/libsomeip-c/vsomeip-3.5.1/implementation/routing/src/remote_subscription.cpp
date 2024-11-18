// Copyright (C) 2018-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/remote_subscription.hpp"

#include <vsomeip/internal/logger.hpp>

namespace vsomeip_v3 {

remote_subscription::remote_subscription()
    : id_(PENDING_SUBSCRIPTION_ID),
      is_initial_(true),
      force_initial_events_(false),
      ttl_(DEFAULT_TTL),
      reserved_(0),
      counter_(0),
      answers_(1),
      final_destination_{destiny::none} {
}

remote_subscription::~remote_subscription() {
}

bool
remote_subscription::operator==(
        const remote_subscription &_other) const {
    auto own_egi = eventgroupinfo_.lock();
    auto other_egi = _other.eventgroupinfo_.lock();
    bool reliable_equal(true);
    if (reliable_ && _other.reliable_) {
        reliable_equal = (reliable_ == _other.reliable_);
    }
    bool unreliable_equal(true);
    if (unreliable_ && _other.unreliable_) {
        unreliable_equal = (unreliable_ == _other.unreliable_);
    }
    return (own_egi && other_egi && own_egi == other_egi && unreliable_equal
            && reliable_equal);
}

bool
remote_subscription::equals(
        const std::shared_ptr<remote_subscription> &_other) const {
    return operator ==(*_other);
}

bool
remote_subscription::address_equals(
        const std::shared_ptr<remote_subscription> &_other) const {
    bool relibale_address_equals(false);
    bool unrelibale_address_equals(false);

    if (reliable_ && (*_other).reliable_)
        relibale_address_equals = (reliable_->get_address()
                == (*_other).reliable_->get_address());
    if (unreliable_ && (*_other).unreliable_)
        unrelibale_address_equals = (unreliable_->get_address()
                == (*_other).unreliable_->get_address());
    return (relibale_address_equals || unrelibale_address_equals);
}

void
remote_subscription::reset(const std::set<client_t> &_clients) {
    auto its_client_state = std::make_pair(
            remote_subscription_state_e::SUBSCRIPTION_PENDING,
            std::chrono::steady_clock::time_point());
    if (_clients.empty()) {
        clients_[0] = its_client_state;
    } else {
        for (const auto &its_client : _clients)
            clients_[its_client] = its_client_state;
    }
}

bool
remote_subscription::is_initial() const {
    return is_initial_;
}

void
remote_subscription::set_initial(const bool _is_initial) {
    is_initial_ = _is_initial;
}

bool
remote_subscription::force_initial_events() const {
    return force_initial_events_;
}

void
remote_subscription::set_force_initial_events(
        const bool _force_initial_events) {
    force_initial_events_ = _force_initial_events;
}

remote_subscription_id_t
remote_subscription::get_id() const {
    return id_;
}

void
remote_subscription::set_id(const remote_subscription_id_t _id) {
    id_ = _id;
}

std::shared_ptr<eventgroupinfo>
remote_subscription::get_eventgroupinfo() const {
    return eventgroupinfo_.lock();
}

void
remote_subscription::set_eventgroupinfo(
        const std::shared_ptr<eventgroupinfo> &_info) {
    eventgroupinfo_ = _info;
}

ttl_t
remote_subscription::get_ttl() const {
    return ttl_;
}

void
remote_subscription::set_ttl(const ttl_t _ttl) {
    ttl_ = _ttl;
}

uint16_t
remote_subscription::get_reserved() const {
    return reserved_;
}

void
remote_subscription::set_reserved(const uint16_t _reserved) {
    reserved_ = _reserved;
}

uint8_t
remote_subscription::get_counter() const {
    return counter_;
}

void
remote_subscription::set_counter(uint8_t _counter) {
    counter_ = _counter;
}

std::set<client_t>
remote_subscription::get_clients() const {
    std::lock_guard<std::mutex> its_lock(mutex_);
    std::set<client_t> its_clients;
    for (const auto &its_item : clients_)
        its_clients.insert(its_item.first);
    return its_clients;
}

bool
remote_subscription::has_client() const {
    std::lock_guard<std::mutex> its_lock(mutex_);
    return (clients_.size() > 0);
}

bool
remote_subscription::has_client(const client_t _client) const {
    std::lock_guard<std::mutex> its_lock(mutex_);
    return (clients_.find(_client) != clients_.end());
}

void
remote_subscription::remove_client(const client_t _client) {
    std::lock_guard<std::mutex> its_lock(mutex_);
    clients_.erase(_client);
}

remote_subscription_state_e
remote_subscription::get_client_state(const client_t _client) const {
    std::lock_guard<std::mutex> its_lock(mutex_);
    auto found_client = clients_.find(_client);
    if (found_client != clients_.end()) {
        return found_client->second.first;
    }
    return remote_subscription_state_e::SUBSCRIPTION_UNKNOWN;
}

void
remote_subscription::set_client_state(const client_t _client,
        remote_subscription_state_e _state) {
    std::lock_guard<std::mutex> its_lock(mutex_);
    auto found_item = clients_.find(_client);
    if (found_item != clients_.end()) {
        found_item->second.first = _state;
        if (found_item->second.second == std::chrono::steady_clock::time_point()
            && (_state == remote_subscription_state_e::SUBSCRIPTION_ACKED
                || _state == remote_subscription_state_e::SUBSCRIPTION_NACKED)) {
            found_item->second.second = std::chrono::steady_clock::now()
                + std::chrono::seconds(ttl_);
        }
    }
}

void
remote_subscription::set_all_client_states(remote_subscription_state_e _state) {
    std::lock_guard<std::mutex> its_lock(mutex_);
    for (auto &its_item : clients_)
        its_item.second.first = _state;
}

std::shared_ptr<endpoint_definition>
remote_subscription::get_subscriber() const {
    return subscriber_;
}

void
remote_subscription::set_subscriber(
        const std::shared_ptr<endpoint_definition> &_subscriber) {
    subscriber_ = _subscriber;
}

std::shared_ptr<endpoint_definition>
remote_subscription::get_reliable() const {
    return reliable_;
}

void
remote_subscription::set_reliable(
        const std::shared_ptr<endpoint_definition> &_reliable) {
    reliable_ = _reliable;
}

std::shared_ptr<endpoint_definition>
remote_subscription::get_unreliable() const {
    return unreliable_;
}

void
remote_subscription::set_unreliable(
        const std::shared_ptr<endpoint_definition> &_unreliable) {
    unreliable_ = _unreliable;
}

bool
remote_subscription::is_pending() const {
    std::lock_guard<std::mutex> its_lock(mutex_);
    for (auto its_client : clients_) {
        if (its_client.second.first
                == remote_subscription_state_e::SUBSCRIPTION_PENDING) {
            return true;
        }
    }
    return false;
}

bool
remote_subscription::is_acknowledged() const {
    std::lock_guard<std::mutex> its_lock(mutex_);
    for (auto its_client : clients_) {
        if (its_client.second.first
                != remote_subscription_state_e::SUBSCRIPTION_ACKED) {
            return false;
        }
    }
    return true;
}

std::chrono::steady_clock::time_point
remote_subscription::get_expiration(const client_t _client) const {
    std::lock_guard<std::mutex> its_lock(mutex_);
    auto found_client = clients_.find(_client);
    if (found_client != clients_.end()) {
        return found_client->second.second;
    }
    return std::chrono::steady_clock::now();
}

std::set<client_t>
remote_subscription::update(const std::set<client_t> &_clients,
        const std::chrono::steady_clock::time_point &_timepoint,
        const bool _is_subscribe) {
    std::set<client_t> its_changed;

    std::lock_guard<std::mutex> its_lock(mutex_);
    for (const auto &its_client : _clients) {
        auto found_client = clients_.find(its_client);
        if (_is_subscribe) {
            if (found_client != clients_.end()) {
                found_client->second.second = _timepoint;
            } else {
                its_changed.insert(its_client);
            }
        } else {
            if (found_client != clients_.end()) {
                its_changed.insert(its_client);
            }
        }
    }

    for (const auto &its_client : its_changed) {
        if (_is_subscribe) {
            clients_[its_client] = std::make_pair(
                    remote_subscription_state_e::SUBSCRIPTION_PENDING, _timepoint);
        } else {
            clients_.erase(its_client);
        }
    }

    return its_changed;
}

std::shared_ptr<remote_subscription>
remote_subscription::get_parent() const {
    return parent_.lock();
}

void
remote_subscription::set_parent(
        const std::shared_ptr<remote_subscription> &_parent) {
    parent_ = _parent;
}

std::uint32_t
remote_subscription::get_answers() const {
    return answers_;
}

void
remote_subscription::set_answers(const std::uint32_t _answers) {
    answers_ = _answers;
}

bool
remote_subscription::get_ip_address(boost::asio::ip::address &_address) const {
    if (reliable_) {
        _address = reliable_->get_address();
        return true;
    }
    else if (unreliable_) {
        _address = unreliable_->get_address();
        return true;
    }
    return false;
}

bool remote_subscription::is_expired() const {
    return this->final_destination_.load(std::memory_order_acquire) == destiny::expire;
}

void remote_subscription::set_expired() {
    this->final_destination_.store(destiny::expire, std::memory_order_release);
}

bool remote_subscription::is_forwarded() const {
    return this->final_destination_.load(std::memory_order_acquire) == destiny::forward;
}

void remote_subscription::set_forwarded() {
    this->final_destination_.store(destiny::forward, std::memory_order_release);
}

} // namespace vsomeip_v3
