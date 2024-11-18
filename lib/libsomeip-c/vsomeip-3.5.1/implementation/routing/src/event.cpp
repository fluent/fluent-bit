// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <chrono>
#include <iomanip>
#include <sstream>
#include <thread>

#include <vsomeip/constants.hpp>
#include <vsomeip/defines.hpp>
#include <vsomeip/message.hpp>
#include <vsomeip/payload.hpp>
#include <vsomeip/runtime.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../include/event.hpp"
#include "../include/routing_manager.hpp"
#include "../../endpoints/include/endpoint_definition.hpp"
#include "../../message/include/payload_impl.hpp"

namespace vsomeip_v3 {

event::event(routing_manager *_routing, bool _is_shadow)
        : routing_(_routing),
          current_(runtime::get()->create_notification()),
          update_(runtime::get()->create_notification()),
          type_(event_type_e::ET_EVENT),
          cycle_timer_(_routing->get_io()),
          cycle_(std::chrono::milliseconds::zero()),
          change_resets_cycle_(false),
          is_updating_on_change_(true),
          is_set_(false),
          is_provided_(false),
          is_shadow_(_is_shadow),
          is_cache_placeholder_(false),
          epsilon_change_func_(std::bind(&event::has_changed, this,
                std::placeholders::_1, std::placeholders::_2)),
          has_default_epsilon_change_func_(true),
          reliability_(reliability_type_e::RT_UNKNOWN) {

}

service_t
event::get_service() const {

    return current_->get_service();
}

void
event::set_service(service_t _service) {

    current_->set_service(_service);
    update_->set_service(_service);
}

instance_t
event::get_instance() const {

    return current_->get_instance();
}

void
event::set_instance(instance_t _instance) {

    current_->set_instance(_instance);
    update_->set_instance(_instance);
}

major_version_t
event::get_version() const {

    return current_->get_interface_version();
}

void
event::set_version(major_version_t _major) {

    current_->set_interface_version(_major);
    update_->set_interface_version(_major);
}

event_t
event::get_event() const {

    return current_->get_method();
}

void
event::set_event(event_t _event) {

    current_->set_method(_event);
    update_->set_method(_event);
}

event_type_e
event::get_type() const {

    return type_;
}

void
event::set_type(const event_type_e _type) {

    type_ = _type;
}

bool
event::is_field() const {

    return (type_ == event_type_e::ET_FIELD);
}

bool
event::is_provided() const {

    return is_provided_;
}

void
event::set_provided(bool _is_provided) {

    is_provided_ = _is_provided;
}

bool event::is_set() const {
    return is_set_;
}

std::shared_ptr<payload>
event::get_payload() const {

    std::lock_guard<std::mutex> its_lock(mutex_);
    return current_->get_payload();
}

void
event::update_payload() {

    std::lock_guard<std::mutex> its_lock(mutex_);
    update_payload_unlocked();
}

void
event::update_payload_unlocked() {

    current_->set_payload(update_->get_payload());
}

void
event::set_payload(const std::shared_ptr<payload> &_payload, bool _force) {

    std::lock_guard<std::mutex> its_lock(mutex_);
    if (is_provided_) {
        if (prepare_update_payload_unlocked(_payload, _force)) {
            if (is_updating_on_change_) {
                if (change_resets_cycle_)
                    stop_cycle();

                notify(_force);

                if (change_resets_cycle_)
                    start_cycle();

                update_payload_unlocked();
            }
        }
    } else {
        VSOMEIP_INFO << __func__ << ":" << __LINE__
                << " Cannot set payload for event ["
                << std::hex << std::setw(4) << std::setfill('0')
                << current_->get_service() << "."
                << current_->get_instance() << "."
                << current_->get_method()
                << "]. It isn't provided";
    }
}

void
event::set_payload(const std::shared_ptr<payload> &_payload, client_t _client,
            bool _force) {

    std::lock_guard<std::mutex> its_lock(mutex_);
    if (is_provided_) {
        if (prepare_update_payload_unlocked(_payload, _force)) {
            if (is_updating_on_change_) {
                notify_one_unlocked(_client, _force);
                update_payload_unlocked();
            }
        }
    } else {
        VSOMEIP_INFO << __func__ << ":" << __LINE__
                << " Cannot set payload for event ["
                << std::hex << std::setw(4) << std::setfill('0')
                << current_->get_service() << "."
                << current_->get_instance() << "."
                << current_->get_method()
                << "]. It isn't provided";
    }
}

void
event::set_payload(const std::shared_ptr<payload> &_payload,
        const client_t _client,
        const std::shared_ptr<endpoint_definition> &_target,
        bool _force) {

    std::lock_guard<std::mutex> its_lock(mutex_);
    if (is_provided_) {
        if (prepare_update_payload_unlocked(_payload, _force)) {
            if (is_updating_on_change_) {
                notify_one_unlocked(_client, _target);
                update_payload_unlocked();
            }
        }
    } else {
        VSOMEIP_INFO << __func__ << ":" << __LINE__
                << " Cannot set payload for event ["
                << std::hex << std::setw(4) << std::setfill('0')
                << current_->get_service() << "."
                << current_->get_instance() << "."
                << current_->get_method()
                << "]. It isn't provided";
    }
}

bool
event::set_payload_notify_pending(const std::shared_ptr<payload> &_payload) {

    std::lock_guard<std::mutex> its_lock(mutex_);
    if (is_provided_ && !is_set_) {

        update_->set_payload(_payload);
        is_set_ = true;

        // Send pending initial events.
        for (const auto &its_target : pending_) {
            set_session();
            routing_->send_to(VSOMEIP_ROUTING_CLIENT,
                    its_target, update_);
        }
        pending_.clear();

        update_payload_unlocked();

        return true;
    }

    return false;
}

void
event::unset_payload(bool _force) {
    std::lock_guard<std::mutex> its_lock(mutex_);
    if (_force) {
        is_set_ = false;
        stop_cycle();
        current_->set_payload(std::make_shared<payload_impl>());
    } else {
        if (is_provided_) {
            is_set_ = false;
            stop_cycle();
            current_->set_payload(std::make_shared<payload_impl>());
        }
    }
}

void
event::set_update_cycle(std::chrono::milliseconds &_cycle) {

    if (is_provided_) {
        std::lock_guard<std::mutex> its_lock(mutex_);
        stop_cycle();
        cycle_ = _cycle;
        start_cycle();
    }
}

void
event::set_change_resets_cycle(bool _change_resets_cycle) {

    change_resets_cycle_ = _change_resets_cycle;
}

void
event::set_update_on_change(bool _is_active) {

    if (is_provided_) {
        is_updating_on_change_ = _is_active;
    }
}

void
event::set_epsilon_change_function(
        const epsilon_change_func_t &_epsilon_change_func) {

    std::lock_guard<std::mutex> its_lock(mutex_);
    if (_epsilon_change_func) {
        epsilon_change_func_ = _epsilon_change_func;
        has_default_epsilon_change_func_ = false;
    }
}

std::set<eventgroup_t>
event::get_eventgroups() const {

    std::set<eventgroup_t> its_eventgroups;
    {
        std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
        for (const auto& e : eventgroups_) {
            its_eventgroups.insert(e.first);
        }
    }
    return its_eventgroups;
}

std::set<eventgroup_t>
event::get_eventgroups(client_t _client) const {

    std::set<eventgroup_t> its_eventgroups;

    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    for (auto e : eventgroups_) {
        if (e.second.find(_client) != e.second.end())
            its_eventgroups.insert(e.first);
    }
    return its_eventgroups;
}

void
event::add_eventgroup(eventgroup_t _eventgroup) {

    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    if (eventgroups_.find(_eventgroup) == eventgroups_.end())
        eventgroups_[_eventgroup] = std::set<client_t>();
}

void
event::set_eventgroups(const std::set<eventgroup_t> &_eventgroups) {

    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    for (auto e : _eventgroups)
        eventgroups_[e] = std::set<client_t>();
}

void
event::update_cbk(boost::system::error_code const &_error) {

    if (!_error) {
        std::lock_guard<std::mutex> its_lock(mutex_);
        cycle_timer_.expires_from_now(cycle_);
        notify(true);
        auto its_handler =
                std::bind(&event::update_cbk, shared_from_this(),
                        std::placeholders::_1);
        cycle_timer_.async_wait(its_handler);
    }
}

void
event::notify(bool _force) {

    if (is_set_) {
        set_session();
        routing_->send(VSOMEIP_ROUTING_CLIENT, update_, _force);
    } else {
        VSOMEIP_INFO << __func__
                << ": Notifying "
                << std::hex << std::setw(4) << std::setfill('0')
                << get_service() << "." << get_instance() << "." << get_event()
                << " failed. Event payload not (yet) set!";
    }
}

void
event::notify_one(client_t _client,
        const std::shared_ptr<endpoint_definition> &_target) {

    if (_target) {
        std::lock_guard<std::mutex> its_lock(mutex_);
        notify_one_unlocked(_client, _target);
    } else {
        VSOMEIP_WARNING << __func__
                << ": Notifying "
                << std::hex << std::setw(4) << std::setfill('0')
                << get_service() << "." << get_instance() << "." << get_event()
                << " failed. Target undefined";
    }
}

void
event::notify_one_unlocked(client_t _client,
        const std::shared_ptr<endpoint_definition> &_target) {

    if (_target) {
        if (is_set_) {
            set_session();
            routing_->send_to(_client, _target, update_);
        } else {
            VSOMEIP_INFO << __func__
                    << ": Notifying "
                    << std::hex << std::setw(4) << std::setfill('0')
                    << get_service() << "." << get_instance() << "." << get_event()
                    << " failed. Event payload not (yet) set!";
            pending_.insert(_target);
        }
    } else {
        VSOMEIP_WARNING << __func__
                << ": Notifying "
                << std::hex << std::setw(4) << std::setfill('0')
                << get_service() << "." << get_instance() << "." << get_event()
                << " failed. Target undefined";
    }
}

void
event::notify_one(client_t _client, bool _force) {

    std::lock_guard<std::mutex> its_lock(mutex_);
    notify_one_unlocked(_client, _force);
}

void
event::notify_one_unlocked(client_t _client, bool _force) {

    if (is_set_) {
        set_session();
        routing_->send(_client, update_, _force);
    } else {
        VSOMEIP_INFO << __func__
                << ": Initial value for ["
                << std::hex << std::setw(4) << std::setfill('0')
                << get_service() << "." << get_instance() << "." << get_event()
                << "] not yet set by the service/client."
                << " Client " << _client
                << " will not receive any initial notification!";
    }
}

bool
event::prepare_update_payload(const std::shared_ptr<payload> &_payload,
        bool _force) {

    std::lock_guard<std::mutex> its_lock(mutex_);
    return prepare_update_payload_unlocked(_payload, _force);
}

bool
event::prepare_update_payload_unlocked(
        const std::shared_ptr<payload> &_payload, bool _force) {

    if (!_force && type_ == event_type_e::ET_FIELD && cycle_ == std::chrono::milliseconds::zero()
        && !has_changed(current_->get_payload(), _payload) && !is_shadow_) {
        return false;
    }

    update_->set_payload(_payload);

    if (!is_set_) {
        start_cycle();
        is_set_ = true;
    }

    return true;
}

void
event::add_ref(client_t _client, bool _is_provided) {

    std::lock_guard<std::mutex> its_lock(refs_mutex_);
    auto its_client = refs_.find(_client);
    if (its_client == refs_.end()) {
        refs_[_client][_is_provided] = 1;
    } else {
        auto its_provided = its_client->second.find(_is_provided);
        if (its_provided == its_client->second.end()) {
            refs_[_client][_is_provided] = 1;
        } else {
            its_provided->second++;
        }
    }
}

void
event::remove_ref(client_t _client, bool _is_provided) {

    std::lock_guard<std::mutex> its_lock(refs_mutex_);
    auto its_client = refs_.find(_client);
    if (its_client != refs_.end()) {
        auto its_provided = its_client->second.find(_is_provided);
        if (its_provided != its_client->second.end()) {
            its_provided->second--;
            if (0 == its_provided->second) {
                its_client->second.erase(_is_provided);
                if (0 == its_client->second.size()) {
                    refs_.erase(_client);
                }
            }
        }
    }
}

bool
event::has_ref() {

    std::lock_guard<std::mutex> its_lock(refs_mutex_);
    return refs_.size() != 0;
}

bool
event::add_subscriber(eventgroup_t _eventgroup,
        const std::shared_ptr<debounce_filter_impl_t> &_filter,
        client_t _client, bool _force) {

    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    bool ret = false;
    if (_force // remote events managed by rm_impl
            || is_provided_ // events provided by rm_proxies
            || is_shadow_ // local events managed by rm_impl
            || is_cache_placeholder_) {

        if (_filter) {
            VSOMEIP_WARNING << "Using client ["
                << std::hex << std::setw(4) << std::setfill('0')
                << _client
                << "] specific filter configuration for SOME/IP event "
                << get_service() << "." << get_instance() << "." << get_event() << ".";
            std::stringstream its_filter_parameters;
            its_filter_parameters << "(on_change="
                    << std::boolalpha << _filter->on_change_
                    << ", interval=" << std::dec << _filter->interval_
                    << ", on_change_resets_interval="
                    << std::boolalpha << _filter->on_change_resets_interval_
                    << ", ignore=[ ";
            for (auto i : _filter->ignore_)
                its_filter_parameters << "(" << std::dec << i.first << ", "
                    << std::hex << std::setw(2) << std::setfill('0')
                    << (int)i.second << ") ";
            its_filter_parameters << "])";
            VSOMEIP_INFO << "Filter parameters: "
                    << its_filter_parameters.str();
            {
                std::scoped_lock lk {filters_mutex_};
                filters_[_client] = [_filter](
                    const std::shared_ptr<payload> &_old,
                    const std::shared_ptr<payload> &_new) {

                    bool is_changed(false), is_elapsed(false);

                    // Check whether we should forward because of changed data
                    if (_filter->on_change_) {
                        length_t its_min_length, its_max_length;

                        if (_old->get_length() < _new->get_length()) {
                            its_min_length = _old->get_length();
                            its_max_length = _new->get_length();
                        } else {
                            its_min_length = _new->get_length();
                            its_max_length = _old->get_length();
                        }

                        // Check whether all additional bytes (if any) are excluded
                        for (length_t i = its_min_length; i < its_max_length; i++) {
                            auto j = _filter->ignore_.find(i);
                            // A change is detected when an additional byte is not
                            // excluded at all or if its exclusion does not cover all
                            // bits
                            if (j == _filter->ignore_.end() || j->second != 0xFF) {
                                is_changed = true;
                                break;
                            }
                        }

                        if (!is_changed) {
                            const byte_t *its_old = _old->get_data();
                            const byte_t *its_new = _new->get_data();
                            for (length_t i = 0; i < its_min_length; i++) {
                                auto j = _filter->ignore_.find(i);
                                if (j == _filter->ignore_.end()) {
                                    if (its_old[i] != its_new[i]) {
                                        is_changed = true;
                                        break;
                                    }
                                } else if (j->second != 0xFF) {
                                    if ((its_old[i] & ~(j->second)) != (its_new[i] & ~(j->second))) {
                                        is_changed = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if (_filter->interval_ > -1) {
                        // Check whether we should forward because of the elapsed time since
                        // we did last time
                        std::chrono::steady_clock::time_point its_current
                            = std::chrono::steady_clock::now();

                        int64_t elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                its_current - _filter->last_forwarded_).count();
                        is_elapsed = (_filter->last_forwarded_ == std::chrono::steady_clock::time_point::max()
                                || elapsed >= _filter->interval_);
                        if (is_elapsed || (is_changed && _filter->on_change_resets_interval_))
                            _filter->last_forwarded_ = its_current;                }

                    return (is_changed || is_elapsed);
                };
            }

            // Create a new callback for this client if filter interval is used
            routing_->register_debounce(_filter, _client, shared_from_this());
        } else {
            std::scoped_lock lk {filters_mutex_};
            filters_.erase(_client);
        }

        ret = eventgroups_[_eventgroup].insert(_client).second;

    } else {
        VSOMEIP_WARNING << __func__ << ": Didnt' insert client "
                << std::hex << std::setw(4) << std::setfill('0') << _client
                << " to eventgroup 0x"
                << std::hex << std::setw(4) << std::setfill('0')
                << get_service() << "." << get_instance() << "."
                << _eventgroup;
    }
    return ret;
}

void
event::remove_subscriber(eventgroup_t _eventgroup, client_t _client) {

    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    auto find_eventgroup = eventgroups_.find(_eventgroup);
    if (find_eventgroup != eventgroups_.end()) {
        find_eventgroup->second.erase(_client);
        routing_->remove_debounce(_client, get_event());
    }
}

bool
event::has_subscriber(eventgroup_t _eventgroup, client_t _client) {

    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    auto find_eventgroup = eventgroups_.find(_eventgroup);
    if (find_eventgroup != eventgroups_.end()) {
        if (_client == ANY_CLIENT) {
            return (find_eventgroup->second.size() > 0);
        } else {
            return (find_eventgroup->second.find(_client)
                    != find_eventgroup->second.end());
        }
    }
    return false;
}

std::set<client_t>
event::get_subscribers() {

    std::set<client_t> its_subscribers;
    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    for (const auto &e : eventgroups_)
        its_subscribers.insert(e.second.begin(), e.second.end());
    return its_subscribers;
}

std::set<client_t>
event::get_filtered_subscribers(bool _force) {

    std::set<client_t> its_subscribers(get_subscribers());
    std::set<client_t> its_filtered_subscribers;

    std::shared_ptr<payload> its_payload, its_payload_update;
    {
        its_payload = current_->get_payload();
        its_payload_update = update_->get_payload();
    }

    bool is_filters_empty = false;
    {
        std::scoped_lock its_lock {filters_mutex_};
        is_filters_empty = filters_.empty();
    }

    if (is_filters_empty) {

        bool must_forward = ((type_ != event_type_e::ET_FIELD
                    && has_default_epsilon_change_func_)
                || _force
                || epsilon_change_func_(its_payload, its_payload_update));

        if (must_forward)
            return its_subscribers;

    } else {
        byte_t is_allowed(0xff);

        std::scoped_lock its_lock {filters_mutex_};
        for (const auto s : its_subscribers) {

            auto its_specific = filters_.find(s);
            if (its_specific != filters_.end()) {
                if (its_specific->second(its_payload, its_payload_update))
                    its_filtered_subscribers.insert(s);
            } else {
                if (is_allowed == 0xff) {
                    is_allowed = ((type_ != event_type_e::ET_FIELD
                            && has_default_epsilon_change_func_)
                        || _force
                        || epsilon_change_func_(its_payload, its_payload_update)
                        ? 0x01 : 0x00);
                }

                if (is_allowed == 0x01)
                    its_filtered_subscribers.insert(s);
            }
        }
    }

    return its_filtered_subscribers;
}

// Get the clients that have pending updates after debounce timeout
void 
event::get_pending_updates(const std::set<client_t> &_clients) {
    if(has_changed(current_->get_payload(), update_->get_payload())) {
        routing_->update_debounce_clients(_clients, get_event());
    }
}

std::set<client_t>
event::update_and_get_filtered_subscribers(
        const std::shared_ptr<payload> &_payload, bool _is_from_remote) {

    std::lock_guard<std::mutex> its_lock(mutex_);

    (void)prepare_update_payload_unlocked(_payload, true);
    auto its_subscribers = get_filtered_subscribers(!_is_from_remote);
    get_pending_updates(its_subscribers);
    if (_is_from_remote)
        update_payload_unlocked();

    return its_subscribers;
}

void
event::clear_subscribers() {

    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    for (auto &e : eventgroups_)
        e.second.clear();
}

bool
event::has_ref(client_t _client, bool _is_provided) {

    std::lock_guard<std::mutex> its_lock(refs_mutex_);
    auto its_client = refs_.find(_client);
    if (its_client != refs_.end()) {
        auto its_provided = its_client->second.find(_is_provided);
        if (its_provided != its_client->second.end()) {
            if(its_provided->second > 0) {
                return true;
            }
        }
    }
    return false;
}

bool
event::is_shadow() const {

    return is_shadow_;
}

void
event::set_shadow(bool _shadow) {

    is_shadow_ = _shadow;
}

bool
event::is_cache_placeholder() const {

    return is_cache_placeholder_;
}

void
event::set_cache_placeholder(bool _is_cache_place_holder) {

    is_cache_placeholder_ = _is_cache_place_holder;
}

void
event::start_cycle() {

    if (!is_shadow_
            && std::chrono::milliseconds::zero() != cycle_) {
        cycle_timer_.expires_from_now(cycle_);
        auto its_handler =
                std::bind(&event::update_cbk, shared_from_this(),
                        std::placeholders::_1);
        cycle_timer_.async_wait(its_handler);
    }
}

void
event::stop_cycle() {

    if (!is_shadow_
            && std::chrono::milliseconds::zero() != cycle_) {
        boost::system::error_code ec;
        cycle_timer_.cancel(ec);
    }
}

bool
event::has_changed(const std::shared_ptr<payload> &_lhs,
        const std::shared_ptr<payload> &_rhs) const {

    if (_lhs) {
        if (_rhs) {
            return !((*_lhs) == (*_rhs));
        } else {
            return false;
        }
    } else {
        if (_rhs) {
            return false;
        }
    }

    return true; // both are nullptr
}

std::set<client_t>
event::get_subscribers(eventgroup_t _eventgroup) {

    std::set<client_t> its_subscribers;
    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    auto found_eventgroup = eventgroups_.find(_eventgroup);
    if (found_eventgroup != eventgroups_.end()) {
        its_subscribers = found_eventgroup->second;
    }
    return its_subscribers;
}

bool
event::is_subscribed(client_t _client) {

    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    for (const auto &egp : eventgroups_) {
        if (egp.second.find(_client) != egp.second.end()) {
            return true;
        }
    }
    return false;
}

reliability_type_e
event::get_reliability() const {

    return reliability_;
}

void
event::set_reliability(const reliability_type_e _reliability) {

    reliability_ = _reliability;
}

void
event::remove_pending(const std::shared_ptr<endpoint_definition> &_target) {

    std::lock_guard<std::mutex> its_lock(mutex_);
    pending_.erase(_target);
}

void
event::set_session() {

    update_->set_session(routing_->get_session(false));
}

} // namespace vsomeip_v3
