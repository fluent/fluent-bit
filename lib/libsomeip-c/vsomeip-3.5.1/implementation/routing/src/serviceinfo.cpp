// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/serviceinfo.hpp"

namespace vsomeip_v3 {

serviceinfo::serviceinfo(service_t _service, instance_t _instance, major_version_t _major,
                         minor_version_t _minor, ttl_t _ttl, bool _is_local) :
    service_(_service),
    instance_(_instance), major_(_major), minor_(_minor), ttl_(0), reliable_(nullptr),
    unreliable_(nullptr), is_local_(_is_local), is_in_mainphase_(false),
    accepting_remote_subscription_(false) {

    std::chrono::seconds ttl = static_cast<std::chrono::seconds> (_ttl);
    ttl_ = std::chrono::duration_cast<std::chrono::milliseconds>(ttl);
}

serviceinfo::serviceinfo(const serviceinfo& _other) :
    service_(_other.service_),
    instance_(_other.instance_),
    major_(_other.major_),
    minor_(_other.minor_),
    ttl_(_other.ttl_),
    reliable_(_other.reliable_),
    unreliable_(_other.unreliable_),
    requesters_(_other.requesters_),
    is_local_(_other.is_local_.load()),
    is_in_mainphase_(_other.is_in_mainphase_.load())
    {}

serviceinfo::~serviceinfo() {
}

service_t serviceinfo::get_service() const {
    return service_;
}

instance_t serviceinfo::get_instance() const {
    return instance_;
}

major_version_t serviceinfo::get_major() const {
  return major_;
}

minor_version_t serviceinfo::get_minor() const {
  return minor_;
}

ttl_t serviceinfo::get_ttl() const {
  std::lock_guard<std::mutex> its_lock(ttl_mutex_);
  ttl_t ttl = static_cast<ttl_t>(std::chrono::duration_cast<std::chrono::seconds>(ttl_).count());
  return ttl;
}

void serviceinfo::set_ttl(ttl_t _ttl) {
  std::lock_guard<std::mutex> its_lock(ttl_mutex_);
  std::chrono::seconds ttl = static_cast<std::chrono::seconds>(_ttl);
  ttl_ = std::chrono::duration_cast<std::chrono::milliseconds> (ttl);
}

std::chrono::milliseconds serviceinfo::get_precise_ttl() const {
  std::lock_guard<std::mutex> its_lock(ttl_mutex_);
  return ttl_;
}

void serviceinfo::set_precise_ttl(std::chrono::milliseconds _precise_ttl) {
  std::lock_guard<std::mutex> its_lock(ttl_mutex_);
  ttl_ = _precise_ttl;
}

std::shared_ptr<endpoint> serviceinfo::get_endpoint(bool _reliable) const {
  std::lock_guard<std::mutex> its_lock(endpoint_mutex_);
  return _reliable ? reliable_ : unreliable_;
}

void serviceinfo::set_endpoint(const std::shared_ptr<endpoint>& _endpoint,
                               bool _reliable) {
  std::lock_guard<std::mutex> its_lock(endpoint_mutex_);
  if (_reliable) {
    reliable_ = _endpoint;
  } else {
    unreliable_ = _endpoint;
  }
}

void serviceinfo::add_client(client_t _client) {
  std::lock_guard<std::mutex> its_lock(requesters_mutex_);
  requesters_.insert(_client);
}

void serviceinfo::remove_client(client_t _client) {
  std::lock_guard<std::mutex> its_lock(requesters_mutex_);
  requesters_.erase(_client);
}

uint32_t serviceinfo::get_requesters_size() {
    std::lock_guard<std::mutex> its_lock(requesters_mutex_);
    return static_cast<std::uint32_t>(requesters_.size());
}

bool serviceinfo::is_local() const {
    return is_local_;
}

bool serviceinfo::is_in_mainphase() const {
    return is_in_mainphase_;
}

void serviceinfo::set_is_in_mainphase(bool _in_mainphase) {
    is_in_mainphase_ = _in_mainphase;
}

bool serviceinfo::is_accepting_remote_subscriptions() const {
    return accepting_remote_subscription_;
}

void serviceinfo::set_accepting_remote_subscriptions(bool _accepting_remote_subscriptions) {
    accepting_remote_subscription_ = _accepting_remote_subscriptions;
    if (!_accepting_remote_subscriptions) {
        std::lock_guard its_lock(accepting_remote_mutex);
        accepting_remote_subscription_from_.clear();
    }
}

void serviceinfo::add_remote_ip(std::string _remote_ip) {
    std::lock_guard its_lock(accepting_remote_mutex);
    accepting_remote_subscription_from_.insert(_remote_ip);
}

std::set<std::string, std::less<>> serviceinfo::get_remote_ip_accepting_sub() {
    std::lock_guard its_lock(accepting_remote_mutex);
    return accepting_remote_subscription_from_;
}

}  // namespace vsomeip_v3
