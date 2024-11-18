// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include <vsomeip/runtime.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../include/routing_manager_base.hpp"
#include "../../configuration/include/debounce_filter_impl.hpp"
#include "../../protocol/include/send_command.hpp"
#include "../../security/include/policy_manager_impl.hpp"
#include "../../security/include/security.hpp"
#ifdef USE_DLT
#include "../../tracing/include/connector_impl.hpp"
#endif
#include "../../utility/include/bithelper.hpp"
#include "../../utility/include/utility.hpp"

namespace vsomeip_v3 {

routing_manager_base::routing_manager_base(routing_manager_host *_host) :
        host_(_host),
        io_(host_->get_io()),
        configuration_(host_->get_configuration()),
        debounce_timer(host_->get_io()),
        routing_state_(routing_state_e::RS_UNKNOWN)
#ifdef USE_DLT
        , tc_(trace::connector_impl::get())
#endif
{
    const std::size_t its_max = configuration_->get_io_thread_count(host_->get_name());
    const uint32_t its_buffer_shrink_threshold =
            configuration_->get_buffer_shrink_threshold();

    for (std::size_t i = 0; i < its_max; ++i) {
        serializers_.push(
            std::make_shared<serializer>(its_buffer_shrink_threshold));
        deserializers_.push(
            std::make_shared<deserializer>(its_buffer_shrink_threshold));
    }

    if (!configuration_->is_local_routing()) {
        auto its_routing_address = configuration_->get_routing_host_address();
        auto its_routing_port = configuration_->get_routing_host_port();
        if (!its_routing_address.is_unspecified() && !its_routing_address.is_multicast()) {
            add_guest(VSOMEIP_ROUTING_CLIENT, its_routing_address, its_routing_port);
        }
    }
}

void routing_manager_base::debounce_timeout_update_cbk(
        const boost::system::error_code& _error, const std::shared_ptr<vsomeip_v3::event>& _event,
        client_t _client, const std::shared_ptr<debounce_filter_impl_t>& _filter) {
    if (!_error) {
        if (!_event) {
            std::lock_guard<std::mutex> its_lock(debounce_mutex_);
            if (debounce_clients_.size() > 0) {
                debounce_timer.expires_from_now(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                                debounce_clients_.begin()->first
                                - std::chrono::steady_clock::now()));
                debounce_timer.async_wait(std::get<2>(debounce_clients_.begin()->second));
            }
            return;
        }

        // _event->get_subscribers() cannot be locked by debounce_mutex_, because it can lead to
        // Lock inversion with remove_subscribes and its eventgroup_mutex!
        auto its_subscribers = _event->get_subscribers();

        bool notify_client {false};
        {
            std::lock_guard<std::mutex> its_lock(debounce_mutex_);
            if (its_subscribers.find(_client) != its_subscribers.end() && _filter) {
                bool is_elapsed {false};
                auto its_current = std::chrono::steady_clock::now();

                int64_t elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                          its_current - _filter->last_forwarded_)
                                          .count();
                is_elapsed =
                        (_filter->last_forwarded_ == std::chrono::steady_clock::time_point::max()
                         || elapsed >= _filter->interval_);

                auto debounce_client = debounce_clients_.begin();
                auto event_id = std::get<3>(debounce_client->second);
                bool has_update = std::get<1>(debounce_client->second);
                if (is_elapsed) {
                    if (std::get<0>(debounce_client->second) == _client && has_update) {
                        notify_client = true;
                        has_update = false;
                    }
                    elapsed = 0;
                }

                debounce_clients_.erase(debounce_client);

                auto timeout = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(_filter->interval_ - elapsed);
                debounce_clients_.emplace(
                        timeout,
                        std::make_tuple(
                                _client, has_update,
                                std::bind(&routing_manager_base::debounce_timeout_update_cbk,
                                          shared_from_this(), std::placeholders::_1, _event,
                                          _client, _filter),
                                event_id));
            }

            if (debounce_clients_.size() > 0) {
                debounce_timer.expires_from_now(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                                debounce_clients_.begin()->first
                                - std::chrono::steady_clock::now()));
                debounce_timer.async_wait(std::get<2>(debounce_clients_.begin()->second));
            }
        } // its_lock(debounce_mutex_)

        // _event->notify_one cannot be locked by debounce_mutex_, because it can lead to
        // Lock inversion with update_and_get_filtered_subscribers and its mutex_!
        if (notify_client) {
            _event->notify_one(_client, false);
        }
    }
}

void routing_manager_base::register_debounce(const std::shared_ptr<debounce_filter_impl_t> &_filter, client_t _client, const  std::shared_ptr<vsomeip_v3::event> &_event) {
    if (_filter->send_current_value_after_ == true) {
        std::lock_guard<std::mutex> its_lock(debounce_mutex_);
        auto sec = std::chrono::milliseconds(_filter->interval_);
        auto timeout = std::chrono::steady_clock::now() + sec;

        auto elem = debounce_clients_.emplace(timeout, std::make_tuple(_client, false, std::bind(&routing_manager_base::debounce_timeout_update_cbk, shared_from_this(),
                std::placeholders::_1, _event, _client, _filter), _event->get_event()));

        if (elem == debounce_clients_.begin()) {
            debounce_timer.cancel();
            debounce_timer.expires_from_now(sec);
            debounce_timer.async_wait(std::get<2>(elem->second));
        }
    }
}

void routing_manager_base::remove_debounce(client_t _client, event_t _event) {
    std::vector<std::chrono::steady_clock::time_point> temp_client_vector;

    std::lock_guard<std::mutex> its_lock(debounce_mutex_);
    for (auto &debounce_client: debounce_clients_) {
        if ((std::get<0>(debounce_client.second) == _client) && (std::get<3>(debounce_client.second) == _event)) {
            temp_client_vector.push_back(debounce_client.first);
        }
    }
    for (auto &elem: temp_client_vector) {
        debounce_clients_.erase(elem);
    }
}

void routing_manager_base::update_debounce_clients(const std::set<client_t> &_clients, event_t _event) {
    std::lock_guard<std::mutex> its_lock(debounce_mutex_);
    for (auto& debounce_client : debounce_clients_) {
        if (_event == std::get<3>(debounce_client.second)) {
            std::get<1>(debounce_client.second) = true;
            for (auto s : _clients) {
                if (std::get<0>(debounce_client.second) == s) {
                    std::get<1>(debounce_client.second) = false;
                }
            }
        }
    }
}

boost::asio::io_context &routing_manager_base::get_io() {

    return io_;
}

client_t routing_manager_base::get_client() const {

    return host_->get_client();
}

void routing_manager_base::set_client(const client_t &_client) {

    host_->set_client(_client);
}

session_t routing_manager_base::get_session(bool _is_request) {
    return host_->get_session(_is_request);
}

const vsomeip_sec_client_t *routing_manager_base::get_sec_client() const {

    return host_->get_sec_client();
}

void routing_manager_base::set_sec_client_port(port_t _port) {

    host_->set_sec_client_port(_port);
}

std::string routing_manager_base::get_client_host() const {
    std::lock_guard<std::mutex> its_env_lock(env_mutex_);
    return env_;
}

void routing_manager_base::set_client_host(const std::string &_client_host) {

    std::lock_guard<std::mutex> its_env_lock(env_mutex_);
    env_ = _client_host;
}

bool routing_manager_base::is_routing_manager() const {
    return false;
}

void routing_manager_base::init(const std::shared_ptr<endpoint_manager_base>& _endpoint_manager) {
    ep_mgr_ = _endpoint_manager;
}

bool routing_manager_base::offer_service(client_t _client,
        service_t _service, instance_t _instance,
        major_version_t _major, minor_version_t _minor) {
    (void)_client;

    // Remote route (incoming only)
    auto its_info = find_service(_service, _instance);
    if (its_info) {
        if (!its_info->is_local()) {
            return false;
        } else if (its_info->get_major() == _major
                && its_info->get_minor() == _minor) {
            its_info->set_ttl(DEFAULT_TTL);
        } else {
            VSOMEIP_ERROR << "rm_base::offer_service service property mismatch ("
                    << std::hex << std::setfill('0')
                    << std::setw(4) << _client << "): ["
                    << std::setw(4) << _service << "."
                    << std::setw(4) << _instance << ":"
                    << std::dec
                    << static_cast<std::uint32_t>(its_info->get_major()) << ":"
                    << its_info->get_minor() << "] passed: "
                    << static_cast<std::uint32_t>(_major) << ":"
                    << _minor;
            return false;
        }
    } else {
        its_info = create_service_info(_service, _instance, _major, _minor,
                DEFAULT_TTL, true);
    }
    {
        std::lock_guard<std::mutex> its_lock(events_mutex_);
        // Set major version for all registered events of this service and instance
        const auto found_service = events_.find(_service);
        if (found_service != events_.end()) {
            const auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                for (const auto &j : found_instance->second) {
                    j.second->set_version(_major);
                }
            }
        }
    }
    return true;
}

void routing_manager_base::stop_offer_service(client_t _client,
        service_t _service, instance_t _instance,
        major_version_t _major, minor_version_t _minor) {
    (void)_client;
    (void)_major;
    (void)_minor;

    std::map<event_t, std::shared_ptr<event> > events;
    {
        std::lock_guard<std::mutex> its_lock(events_mutex_);
        auto its_events_service = events_.find(_service);
        if (its_events_service != events_.end()) {
            auto its_events_instance = its_events_service->second.find(_instance);
            if (its_events_instance != its_events_service->second.end()) {
                for (auto &e : its_events_instance->second)
                    events[e.first] = e.second;

            }
        }
    }
    for (auto &e : events) {
        e.second->unset_payload();
        e.second->clear_subscribers();
    }
}

void routing_manager_base::request_service(client_t _client,
        service_t _service, instance_t _instance,
        major_version_t _major, minor_version_t _minor) {
    auto its_info = find_service(_service, _instance);
    if (its_info) {
        if ((_major == its_info->get_major()
                || DEFAULT_MAJOR == its_info->get_major()
                || ANY_MAJOR == _major)
                && (_minor <= its_info->get_minor()
                    || DEFAULT_MINOR == its_info->get_minor()
                    || _minor == ANY_MINOR)) {
            its_info->add_client(_client);
        } else {
            VSOMEIP_ERROR << "rm_base::request_service service property mismatch ("
                    << std::hex << std::setfill('0')
                    << std::setw(4) << _client << "): ["
                    << std::setw(4) << _service << "."
                    << std::setw(4) << _instance << ":"
                    << std::dec
                    << static_cast<std::uint32_t>(its_info->get_major()) << ":"
                    << its_info->get_minor() << "] passed: "
                    << static_cast<std::uint32_t>(_major) << ":"
                    << _minor;
        }
    }
}

void routing_manager_base::release_service(client_t _client,
        service_t _service, instance_t _instance) {
    auto its_info = find_service(_service, _instance);
    if (its_info) {
        its_info->remove_client(_client);
    }
    {
        std::lock_guard<std::mutex> its_service_guard(local_services_mutex_);
        auto found_service = local_services_history_.find(_service);
        if (found_service != local_services_history_.end()) {
           auto found_instance = found_service->second.find(_instance);
           if (found_instance != found_service->second.end()) {
               found_service->second.erase(_instance);
               if (found_service->second.empty()) {
                   local_services_history_.erase(_service);
               }
           }
        }
    }
}

void routing_manager_base::register_event(client_t _client,
        service_t _service, instance_t _instance,
        event_t _notifier,
        const std::set<eventgroup_t> &_eventgroups,
        const event_type_e _type,
        reliability_type_e _reliability,
        std::chrono::milliseconds _cycle, bool _change_resets_cycle,
        bool _update_on_change,
        epsilon_change_func_t _epsilon_change_func,
        bool _is_provided, bool _is_shadow, bool _is_cache_placeholder) {
    std::lock_guard<std::mutex> its_registration_lock(event_registration_mutex_);

    auto determine_event_reliability = [this, &_service, &_instance,
                                        &_notifier, &_reliability]() {
        reliability_type_e its_reliability =
                configuration_->get_event_reliability(_service, _instance, _notifier);
        if (its_reliability != reliability_type_e::RT_UNKNOWN) {
            // event was explicitly configured -> overwrite value passed via API
            return its_reliability;
        } else if (_reliability != reliability_type_e::RT_UNKNOWN) {
            // use value provided via API
            return _reliability;
        } else { // automatic mode, user service' reliability
            return configuration_->get_service_reliability(_service, _instance);
        }
    };

    std::shared_ptr<event> its_event = find_event(_service, _instance, _notifier);
    bool transfer_subscriptions_from_any_event(false);
    if (its_event) {
        if (!its_event->is_cache_placeholder()) {
            if (_type == its_event->get_type()
                    || its_event->get_type() == event_type_e::ET_UNKNOWN) {
                if (_is_provided) {
                    its_event->set_provided(true);
                    its_event->set_reliability(determine_event_reliability());
                }
                if (_is_shadow && _is_provided) {
                    its_event->set_shadow(_is_shadow);
                }
                if (_client == host_->get_client() && _is_provided) {
                    its_event->set_shadow(false);
                    its_event->set_update_on_change(_update_on_change);
                }
                for (auto eg : _eventgroups) {
                    its_event->add_eventgroup(eg);
                }
                transfer_subscriptions_from_any_event = true;
            } else {
#ifdef VSOMEIP_ENABLE_COMPAT
                if (!(its_event->get_type() == event_type_e::ET_SELECTIVE_EVENT
                        && _type == event_type_e::ET_EVENT))
#endif
                    VSOMEIP_ERROR << "Event registration update failed. "
                            "Specified arguments do not match existing registration.";
            }
        } else {
            // the found event was a placeholder for caching.
            // update it with the real values
            if (_type != event_type_e::ET_FIELD) {
                // don't cache payload for non-fields
                its_event->unset_payload(true);
            }
            if (_is_shadow && _is_provided) {
                its_event->set_shadow(_is_shadow);
            }
            if (_client == host_->get_client() && _is_provided) {
                its_event->set_shadow(false);
                its_event->set_update_on_change(_update_on_change);
            }
            its_event->set_type(_type);
            its_event->set_reliability(determine_event_reliability());
            its_event->set_provided(_is_provided);
            its_event->set_cache_placeholder(false);
            std::shared_ptr<serviceinfo> its_service = find_service(_service, _instance);
            if (its_service) {
                its_event->set_version(its_service->get_major());
            }
            if (_eventgroups.size() == 0) { // No eventgroup specified
                std::set<eventgroup_t> its_eventgroups;
                its_eventgroups.insert(_notifier);
                its_event->set_eventgroups(its_eventgroups);
            } else {
                for (auto eg : _eventgroups) {
                    its_event->add_eventgroup(eg);
                }
            }

            its_event->set_epsilon_change_function(_epsilon_change_func);
            its_event->set_change_resets_cycle(_change_resets_cycle);
            its_event->set_update_cycle(_cycle);
        }
    } else {
        its_event = std::make_shared<event>(this, _is_shadow);
        its_event->set_service(_service);
        its_event->set_instance(_instance);
        its_event->set_event(_notifier);
        its_event->set_type(_type);
        its_event->set_reliability(determine_event_reliability());
        its_event->set_provided(_is_provided);
        its_event->set_cache_placeholder(_is_cache_placeholder);
        std::shared_ptr<serviceinfo> its_service = find_service(_service, _instance);
        if (its_service) {
            its_event->set_version(its_service->get_major());
        }

        if (_eventgroups.size() == 0) { // No eventgroup specified
            std::set<eventgroup_t> its_eventgroups;
            its_eventgroups.insert(_notifier);
            its_event->set_eventgroups(its_eventgroups);
        } else {
            its_event->set_eventgroups(_eventgroups);
        }

        if ((_is_shadow || is_routing_manager()) && !_epsilon_change_func) {
            std::shared_ptr<debounce_filter_impl_t> its_debounce
                = configuration_->get_debounce(host_->get_name(), _service, _instance, _notifier);
            if (its_debounce) {
                std::stringstream its_debounce_parameters;
                its_debounce_parameters << "(on_change="
                        << (its_debounce->on_change_ ? "true" : "false")
                        << ", ignore=[ ";
                for (auto i : its_debounce->ignore_)
                   its_debounce_parameters << "(" << std::dec << i.first
                           << ", " << std::hex << (int)i.second << ") ";
                its_debounce_parameters << "], interval="
                        << std::dec << its_debounce->interval_ << ")";

                VSOMEIP_WARNING << "Using debounce configuration for "
                        << " SOME/IP event "
                        << std::hex << std::setw(4) << std::setfill('0')
                        << _service << "."
                        << std::hex << std::setw(4) << std::setfill('0')
                        << _instance << "."
                        << std::hex << std::setw(4) << std::setfill('0')
                        << _notifier << "."
                        << " Debounce parameters: "
                        << its_debounce_parameters.str();

                _epsilon_change_func = [its_debounce](
                    const std::shared_ptr<payload> &_old,
                    const std::shared_ptr<payload> &_new) {

                    bool is_changed(false), is_elapsed(false);

                    // Check whether we should forward because of changed data
                    if (its_debounce->on_change_) {
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
                            auto j = its_debounce->ignore_.find(i);
                            // A change is detected when an additional byte is not
                            // excluded at all or if its exclusion does not cover all
                            // bits
                            if (j == its_debounce->ignore_.end() || j->second != 0xFF) {
                                is_changed = true;
                                break;
                            }
                        }

                        if (!is_changed) {
                            const byte_t *its_old = _old->get_data();
                            const byte_t *its_new = _new->get_data();
                            for (length_t i = 0; i < its_min_length; i++) {
                                auto j = its_debounce->ignore_.find(i);
                                if (j == its_debounce->ignore_.end()) {
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

                    if (its_debounce->interval_ > -1) {
                        // Check whether we should forward because of the elapsed time since
                        // we did last time
                        std::chrono::steady_clock::time_point its_current
                            = std::chrono::steady_clock::now();
                        int64_t elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                           its_current - its_debounce->last_forwarded_).count();
                        is_elapsed = (its_debounce->last_forwarded_ == std::chrono::steady_clock::time_point::max()
                                || elapsed >= its_debounce->interval_);
                        if (is_elapsed || (is_changed && its_debounce->on_change_resets_interval_))
                            its_debounce->last_forwarded_ = its_current;
                    }
                    return (is_changed || is_elapsed);
                };

                // Create a new callback for this client if filter interval is used
                register_debounce(its_debounce, _client, its_event);
            } else {
                if (_is_shadow || !is_routing_manager()) {
                    _epsilon_change_func = [](const std::shared_ptr<payload> &_old,
                                        const std::shared_ptr<payload> &_new) {
                        (void)_old;
                        (void)_new;
                        return true;
                    };
                }
            }
        }

        its_event->set_epsilon_change_function(_epsilon_change_func);
        its_event->set_change_resets_cycle(_change_resets_cycle);
        its_event->set_update_cycle(_cycle);
        its_event->set_update_on_change(_update_on_change);

        if (_is_provided) {
            transfer_subscriptions_from_any_event = true;
        }
    }

    if (transfer_subscriptions_from_any_event) {
        // check if someone subscribed to ANY_EVENT and the subscription
        // was stored in the cache placeholder. Move the subscribers
        // into new event
        std::shared_ptr<event> its_any_event =
                find_event(_service, _instance, ANY_EVENT);
        if (its_any_event) {
            std::set<eventgroup_t> any_events_eventgroups =
                    its_any_event->get_eventgroups();
            for (eventgroup_t eventgroup : _eventgroups) {
                auto found_eg = any_events_eventgroups.find(eventgroup);
                if (found_eg != any_events_eventgroups.end()) {
                    std::set<client_t> its_any_event_subscribers =
                            its_any_event->get_subscribers(eventgroup);
                    for (const client_t subscriber : its_any_event_subscribers) {
                        its_event->add_subscriber(eventgroup, nullptr, subscriber, true);
                    }
                }
            }
        }
    }
    if(!_is_cache_placeholder) {
        its_event->add_ref(_client, _is_provided);
    }

    for (auto eg : _eventgroups) {
        std::shared_ptr<eventgroupinfo> its_eventgroupinfo
            = find_eventgroup(_service, _instance, eg);
        if (!its_eventgroupinfo) {
            its_eventgroupinfo = std::make_shared<eventgroupinfo>();
            its_eventgroupinfo->set_service(_service);
            its_eventgroupinfo->set_instance(_instance);
            its_eventgroupinfo->set_eventgroup(eg);
            its_eventgroupinfo->set_max_remote_subscribers(
                    configuration_->get_max_remote_subscribers());
            std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
            eventgroups_[_service][_instance][eg] = its_eventgroupinfo;
        }
        its_eventgroupinfo->add_event(its_event);
    }

    std::lock_guard<std::mutex> its_lock(events_mutex_);
    events_[_service][_instance][_notifier] = its_event;
}

void routing_manager_base::unregister_event(client_t _client, service_t _service, instance_t _instance,
            event_t _event, bool _is_provided) {
    (void)_client;
    std::shared_ptr<event> its_unrefed_event;
    {
        std::lock_guard<std::mutex> its_lock(events_mutex_);
        auto found_service = events_.find(_service);
        if (found_service != events_.end()) {
            auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                auto found_event = found_instance->second.find(_event);
                if (found_event != found_instance->second.end()) {
                    auto its_event = found_event->second;
                    its_event->remove_ref(_client, _is_provided);
                    if (!its_event->has_ref()) {
                        its_unrefed_event = its_event;
                        found_instance->second.erase(found_event);
                    } else if (_is_provided) {
                        its_event->set_provided(false);
                    }
                }
            }
        }
    }
    if (its_unrefed_event) {
        auto its_eventgroups = its_unrefed_event->get_eventgroups();
        for (auto eg : its_eventgroups) {
            std::shared_ptr<eventgroupinfo> its_eventgroup_info
                = find_eventgroup(_service, _instance, eg);
            if (its_eventgroup_info) {
                its_eventgroup_info->remove_event(its_unrefed_event);
                if (0 == its_eventgroup_info->get_events().size()) {
                    remove_eventgroup_info(_service, _instance, eg);
                }
            }
        }
    }
}

std::set<std::shared_ptr<event>> routing_manager_base::find_events(
        service_t _service, instance_t _instance,
        eventgroup_t _eventgroup) const {
    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    std::set<std::shared_ptr<event> > its_events;
    auto found_service = eventgroups_.find(_service);
    if (found_service != eventgroups_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            auto found_eventgroup = found_instance->second.find(_eventgroup);
            if (found_eventgroup != found_instance->second.end()) {
                return found_eventgroup->second->get_events();
            }
        }
    }
    return its_events;
}

std::vector<event_t> routing_manager_base::find_events(
        service_t _service, instance_t _instance) const {
    std::vector<event_t> its_events;
    std::lock_guard<std::mutex> its_lock(events_mutex_);
    const auto found_service = events_.find(_service);
    if (found_service != events_.end()) {
        const auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            for (const auto& e : found_instance->second) {
                its_events.push_back(e.first);
            }
        }
    }
    return its_events;
}

bool routing_manager_base::is_response_allowed(client_t _sender, service_t _service,
        instance_t _instance, method_t _method) {

    if (!configuration_->is_security_enabled()
        || !configuration_->is_local_routing()) {
        return true;
    }

    {
        std::lock_guard<std::mutex> its_lock(local_services_mutex_);
        if (_sender == find_local_client_unlocked(_service, _instance)) {
            // sender is still offering the service
            return true;
        }

        auto found_service = local_services_history_.find(_service);
        if (found_service != local_services_history_.end()) {
           auto found_instance = found_service->second.find(_instance);
           if (found_instance != found_service->second.end()) {
               auto found_client = found_instance->second.find(_sender);
               if (found_client != found_instance->second.end()) {
                   // sender was offering the service and is still connected
                   return true;
               }
           }
        }
    }

    // service is now offered by another client
    // or service is not offered at all
    std::string security_mode_text = "!";
    if (!configuration_->is_security_audit()) {
        security_mode_text = ", but will be allowed due to audit mode is active!";
    }

    VSOMEIP_WARNING << "vSomeIP Security: Client 0x" << std::hex << get_client()
            << " : routing_manager_base::is_response_allowed: "
            << "received a response from client 0x" << _sender
            << " which does not offer service/instance/method "
            << _service << "/" << _instance << "/" << _method
            << security_mode_text;

    return !configuration_->is_security_audit();
}

bool routing_manager_base::is_subscribe_to_any_event_allowed(
        const vsomeip_sec_client_t *_sec_client, client_t _client,
        service_t _service, instance_t _instance, eventgroup_t _eventgroup) {

    bool is_allowed(true);

    auto its_eventgroup = find_eventgroup(_service, _instance, _eventgroup);
    if (its_eventgroup) {
        for (const auto& e : its_eventgroup->get_events()) {
            if (VSOMEIP_SEC_OK != configuration_->get_security()->is_client_allowed_to_access_member(
                    _sec_client, _service, _instance, e->get_event())) {
                VSOMEIP_WARNING << "vSomeIP Security: Client 0x" << std::hex
                    << _client << " : routing_manager_base::is_subscribe_to_any_event_allowed: "
                    << "subscribes to service/instance/event "
                    << _service << "/" << _instance << "/" << e->get_event()
                    << " which violates the security policy!";
                is_allowed = false;
                break;
            }
        }
    }

    return is_allowed;
}

void routing_manager_base::add_known_client(client_t _client, const std::string &_client_host) {
#if !defined(VSOMEIP_DISABLE_SECURITY) && (defined(__linux__) || defined(ANDROID))
    std::lock_guard<std::mutex> lazy_lock(add_known_client_mutex_);
    if (configuration_->is_security_enabled() && !configuration_->is_security_external()) {
        //Ignore if we have already loaded the policy extension
        policy_manager_impl::policy_loaded_e policy_loaded
            = configuration_->get_policy_manager()->is_policy_extension_loaded(_client_host);

        if (policy_loaded == policy_manager_impl::policy_loaded_e::POLICY_PATH_FOUND_AND_NOT_LOADED)
        {
            if (configuration_->lazy_load_security(_client_host)) {
                VSOMEIP_INFO << __func__ << " vSomeIP Security: Loaded security policies for host: "
                        << _client_host
                        << " at UID/GID: " << std::dec << getuid() << "/" << getgid();
            }
        } else if (policy_loaded == policy_manager_impl::policy_loaded_e::POLICY_PATH_INEXISTENT) {
            if (configuration_->lazy_load_security(_client_host))
            {
                VSOMEIP_INFO << __func__ << " vSomeIP Security: Loaded security policies for host: "
                    << _client_host
                    << " at UID/GID: " << std::dec << getuid() << "/" << getgid();
            } else if (configuration_->lazy_load_security(get_client_host())) { //necessary for lazy loading from inside android container
                VSOMEIP_INFO << __func__ << " vSomeIP Security: Loaded security policies for host: "
                    << get_client_host()
                    << " at UID/GID: " << std::dec << getuid() << "/" << getgid();
            }
        }
    }
#endif
    std::lock_guard<std::mutex> its_lock(known_clients_mutex_);
    known_clients_[_client] = _client_host;
}

void routing_manager_base::subscribe(client_t _client,
        const vsomeip_sec_client_t *_sec_client,
        service_t _service, instance_t _instance,
        eventgroup_t _eventgroup, major_version_t _major,
        event_t _event, const std::shared_ptr<debounce_filter_impl_t> &_filter) {

    (void)_major;
    (void)_sec_client;

    std::set<event_t> its_already_subscribed_events;
    bool inserted = insert_subscription(_service, _instance, _eventgroup,
            _event, _filter, _client, &its_already_subscribed_events);
    if (inserted) {
        notify_one_current_value(_client, _service, _instance, _eventgroup,
                _event, its_already_subscribed_events);
    }
}

void routing_manager_base::unsubscribe(client_t _client,
        const vsomeip_sec_client_t *_sec_client,
        service_t _service, instance_t _instance, eventgroup_t _eventgroup,
        event_t _event) {

    (void)_sec_client;

    if (_event != ANY_EVENT) {
        auto its_event = find_event(_service, _instance, _event);
        if (its_event) {
            its_event->remove_subscriber(_eventgroup, _client);
        }
    } else {
        auto its_eventgroup = find_eventgroup(_service, _instance, _eventgroup);
        if (its_eventgroup) {
            for (const auto &e : its_eventgroup->get_events()) {
                if (e)
                    e->remove_subscriber(_eventgroup, _client);
            }
        }
    }
}

void routing_manager_base::notify(service_t _service, instance_t _instance,
            event_t _event, std::shared_ptr<payload> _payload,
            bool _force) {

    std::shared_ptr<event> its_event = find_event(_service, _instance, _event);
    if (its_event) {
        its_event->set_payload(_payload, _force);
    } else {
        VSOMEIP_WARNING << "Attempt to update the undefined event/field ["
            << std::hex << _service << "." << _instance << "." << _event
            << "]";
    }
}

void routing_manager_base::notify_one(service_t _service, instance_t _instance,
            event_t _event, std::shared_ptr<payload> _payload,
            client_t _client, bool _force
#ifdef VSOMEIP_ENABLE_COMPAT
            , bool _remote_subscriber
#endif
            ) {
    std::shared_ptr<event> its_event = find_event(_service, _instance, _event);
    if (its_event) {
        // Event is valid for service/instance
        bool found_eventgroup(false);
        bool already_subscribed(false);
#ifdef VSOMEIP_ENABLE_COMPAT
        eventgroup_t valid_group = 0;
        subscription_state_e its_subscription_state(subscription_state_e::SUBSCRIPTION_NOT_ACKNOWLEDGED);
#endif
        // Iterate over all groups of the event to ensure at least
        // one valid eventgroup for service/instance exists.
        for (auto its_group : its_event->get_eventgroups()) {
            auto its_eventgroup = find_eventgroup(_service, _instance, its_group);
            if (its_eventgroup) {
                // Eventgroup is valid for service/instance
                found_eventgroup = true;
#ifdef VSOMEIP_ENABLE_COMPAT
                valid_group = its_group;
                its_subscription_state = get_incoming_subscription_state(_client, _service,
                        _instance, valid_group, _event);
#endif
                if (ep_mgr_->find_local(_client)) {
                    already_subscribed = its_event->has_subscriber(its_group, _client);
#ifdef VSOMEIP_ENABLE_COMPAT
                } else if (subscription_state_e::IS_SUBSCRIBING != its_subscription_state
                        || _remote_subscriber) {
                    // Remotes always needs to be marked as subscribed here if they are not currently subscribing
#else
                } else {
                    // Remotes always needs to be marked as subscribed here
#endif
                    already_subscribed = true;
                }
                break;
            }
        }
        if (found_eventgroup) {
            if (already_subscribed) {
                its_event->set_payload(_payload, _client, _force);
            }
#ifdef VSOMEIP_ENABLE_COMPAT
            else {
                // cache notification if subscription is in progress
                if (subscription_state_e::IS_SUBSCRIBING == its_subscription_state) {
                    VSOMEIP_INFO << "routing_manager_base::notify_one("
                        << std::hex << std::setfill('0')
                        << std::setw(4) << _client << "): ["
                        << std::setw(4) << _service << "."
                        << std::setw(4) << _instance << "."
                        << std::setw(4) << valid_group << "."
                        << std::setw(4) << _event << "]"
                        << " insert pending notification!";
                    std::shared_ptr<message> its_notification
                        = runtime::get()->create_notification();
                    its_notification->set_service(_service);
                    its_notification->set_instance(_instance);
                    its_notification->set_method(_event);
                    its_notification->set_payload(_payload);
                    auto service_info = find_service(_service, _instance);
                    if (service_info) {
                        its_notification->set_interface_version(service_info->get_major());
                    }
                    {
                        std::lock_guard<std::recursive_mutex> its_lock(pending_notify_ones_mutex_);
                        pending_notify_ones_[_service][_instance][valid_group] = its_notification;
                    }
                }
            }
#endif
        }
    } else {
        VSOMEIP_WARNING << "Attempt to update the undefined event/field ["
            << std::hex << _service << "." << _instance << "." << _event
            << "]";
    }
}

#ifdef VSOMEIP_ENABLE_COMPAT
void routing_manager_base::send_pending_notify_ones(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, client_t _client, bool _remote_subscriber) {
    std::lock_guard<std::recursive_mutex> its_lock(pending_notify_ones_mutex_);
    auto its_service = pending_notify_ones_.find(_service);
    if (its_service != pending_notify_ones_.end()) {
        auto its_instance = its_service->second.find(_instance);
        if (its_instance != its_service->second.end()) {
            auto its_group = its_instance->second.find(_eventgroup);
            if (its_group != its_instance->second.end()) {
                VSOMEIP_INFO << "routing_manager_base::send_pending_notify_ones("
                    << std::hex << std::setfill('0')
                    << std::setw(4) << _client << "): ["
                    << std::setw(4) << _service << "."
                    << std::setw(4) << _instance << "."
                    << std::setw(4) << _eventgroup << "."
                    << std::setw(4) << its_group->second->get_method() << "]";

                notify_one(_service, _instance, its_group->second->get_method(),
                        its_group->second->get_payload(), _client, false, _remote_subscriber);
                its_instance->second.erase(_eventgroup);
            }
        }
    }
}
#endif

void routing_manager_base::unset_all_eventpayloads(service_t _service,
                                                   instance_t _instance) {
    std::set<std::shared_ptr<event>> its_events;
    {
        std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
        const auto found_service = eventgroups_.find(_service);
        if (found_service != eventgroups_.end()) {
            const auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                for (const auto &eventgroupinfo : found_instance->second) {
                    for (const auto &event : eventgroupinfo.second->get_events()) {
                        its_events.insert(event);
                    }
                }
            }
        }
    }
    for (const auto &e : its_events) {
        e->unset_payload(true);
    }
}

void routing_manager_base::unset_all_eventpayloads(service_t _service,
                                                   instance_t _instance,
                                                   eventgroup_t _eventgroup) {
    std::set<std::shared_ptr<event>> its_events;
    {
        std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
        const auto found_service = eventgroups_.find(_service);
        if (found_service != eventgroups_.end()) {
            const auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                const auto found_eventgroup = found_instance->second.find(_eventgroup);
                if (found_eventgroup != found_instance->second.end()) {
                    for (const auto &event : found_eventgroup->second->get_events()) {
                        its_events.insert(event);
                    }
                }
            }
        }
    }
    for (const auto &e : its_events) {
        e->unset_payload(true);
    }
}

void routing_manager_base::notify_one_current_value(
        client_t _client, service_t _service, instance_t _instance,
        eventgroup_t _eventgroup, event_t _event,
        const std::set<event_t> &_events_to_exclude) {
    if (_event != ANY_EVENT) {
        std::shared_ptr<event> its_event = find_event(_service, _instance, _event);
        if (its_event && its_event->is_field())
            its_event->notify_one(_client, false);
    } else {
        auto its_eventgroup = find_eventgroup(_service, _instance, _eventgroup);
        if (its_eventgroup) {
            std::set<std::shared_ptr<event> > its_events = its_eventgroup->get_events();
            for (const auto &e : its_events) {
                if (e->is_field()
                        && _events_to_exclude.find(e->get_event())
                                == _events_to_exclude.end()) {
                    e->notify_one(_client, false);
                }
            }
        }
    }
}

bool routing_manager_base::send(client_t _client,
        std::shared_ptr<message> _message, bool _force) {
    bool is_sent(false);
    if (utility::is_request(_message->get_message_type())) {
        _message->set_client(_client);
    }

    std::shared_ptr<serializer> its_serializer(get_serializer());
    if (its_serializer->serialize(_message.get())) {
        is_sent = send(_client, its_serializer->get_data(),
                its_serializer->get_size(), _message->get_instance(),
                _message->is_reliable(), get_client(), get_sec_client(),
                0, false, _force);
        its_serializer->reset();
        put_serializer(its_serializer);
    } else {
        VSOMEIP_ERROR << "Failed to serialize message. Check message size!";
    }
    return is_sent;
}

// ********************************* PROTECTED **************************************
std::shared_ptr<serviceinfo> routing_manager_base::create_service_info(
        service_t _service, instance_t _instance, major_version_t _major,
        minor_version_t _minor, ttl_t _ttl, bool _is_local_service) {
    std::shared_ptr<serviceinfo> its_info =
            std::make_shared<serviceinfo>(_service, _instance,
                    _major, _minor, _ttl, _is_local_service);
    {
        std::lock_guard<std::mutex> its_lock(services_mutex_);
        services_[_service][_instance] = its_info;
    }
    if (!_is_local_service) {
        std::lock_guard<std::mutex> its_lock(services_remote_mutex_);
        services_remote_[_service][_instance] = its_info;
    }
    return its_info;
}

std::shared_ptr<serviceinfo> routing_manager_base::find_service(
        service_t _service, instance_t _instance) const {
    std::shared_ptr<serviceinfo> its_info;
    std::lock_guard<std::mutex> its_lock(services_mutex_);
    auto found_service = services_.find(_service);
    if (found_service != services_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            its_info = found_instance->second;
        }
    }
    return its_info;
}

void routing_manager_base::clear_service_info(service_t _service, instance_t _instance,
        bool _reliable) {
    std::shared_ptr<serviceinfo> its_info(find_service(_service, _instance));
    if (!its_info) {
        return;
    }

    bool deleted_instance(false);
    bool deleted_service(false);
    {
        std::lock_guard<std::mutex> its_lock(services_mutex_);

        // Clear service_info and service_group
        std::shared_ptr<endpoint> its_empty_endpoint;
        if (!its_info->get_endpoint(!_reliable)) {
            if (1 >= services_[_service].size()) {
                services_.erase(_service);
                deleted_service = true;
            } else {
                services_[_service].erase(_instance);
                deleted_instance = true;
            }
        } else {
            its_info->set_endpoint(its_empty_endpoint, _reliable);
        }
    }

    if ((deleted_instance || deleted_service) && !its_info->is_local()) {
        std::lock_guard<std::mutex> its_lock(services_remote_mutex_);
        if (deleted_service) {
            services_remote_.erase(_service);
        } else if (deleted_instance) {
            services_remote_[_service].erase(_instance);
        }
    }
}

services_t routing_manager_base::get_services() const {
    std::lock_guard<std::mutex> its_lock(services_mutex_);
    return services_;
}

services_t routing_manager_base::get_services_remote() const {
    std::lock_guard<std::mutex> its_lock(services_remote_mutex_);
    return services_remote_;
}

bool routing_manager_base::is_available(service_t _service, instance_t _instance,
        major_version_t _major) {
    bool available(false);
    std::lock_guard<std::mutex> its_lock(local_services_mutex_);
    auto its_service = local_services_.find(_service);
    if (its_service != local_services_.end()) {
        if (_instance == ANY_INSTANCE) {
            return true;
        }
        auto its_instance = its_service->second.find(_instance);
        if (its_instance != its_service->second.end()) {
            if (_major == ANY_MAJOR) {
                return true;
            }
            if (std::get<0>(its_instance->second) == _major) {
                available = true;
            }
        }
    }
    return available;
}

std::set<client_t> routing_manager_base::find_local_clients(service_t _service, instance_t _instance) {
    std::set<client_t> its_clients;
    std::lock_guard<std::mutex> its_lock(local_services_mutex_);
    auto its_service = local_services_.find(_service);
    if (its_service != local_services_.end()) {
        if (_instance == ANY_INSTANCE) {
            for (auto its_instance : its_service->second) {
                its_clients.insert(std::get<2>(its_instance.second));
           }
        } else {
            auto its_instance = its_service->second.find(_instance);
            if (its_instance != its_service->second.end()) {
                its_clients.insert(std::get<2>(its_instance->second));
            }
        }
    }
    return its_clients;
}

client_t routing_manager_base::find_local_client(service_t _service,
                                                 instance_t _instance) const {
    std::lock_guard<std::mutex> its_lock(local_services_mutex_);
    return find_local_client_unlocked(_service, _instance);
}

client_t routing_manager_base::find_local_client_unlocked(service_t _service,
                                                 instance_t _instance) const {
    client_t its_client(VSOMEIP_ROUTING_CLIENT);
    auto its_service = local_services_.find(_service);
    if (its_service != local_services_.end()) {
        auto its_instance = its_service->second.find(_instance);
        if (its_instance != its_service->second.end()) {
            its_client = std::get<2>(its_instance->second);
        }
    }
    return its_client;
}

void routing_manager_base::remove_local(client_t _client, bool _remove_uid) {
    remove_local(_client, get_subscriptions(_client), _remove_uid);
}

void routing_manager_base::remove_local(client_t _client,
                  const std::set<std::tuple<service_t, instance_t, eventgroup_t>>& _subscribed_eventgroups,
                  bool _remove_sec_client) {

    vsomeip_sec_client_t its_sec_client;
    configuration_->get_policy_manager()->get_client_to_sec_client_mapping(_client, its_sec_client);

    if (_remove_sec_client) {
        configuration_->get_policy_manager()->remove_client_to_sec_client_mapping(_client);
    }
    for (auto its_subscription : _subscribed_eventgroups) {
        host_->on_subscription(std::get<0>(its_subscription), std::get<1>(its_subscription),
                std::get<2>(its_subscription), _client,
                &its_sec_client, get_env(_client),
                false, [](const bool _subscription_accepted){ (void)_subscription_accepted; });
        routing_manager_base::unsubscribe(_client, &its_sec_client, std::get<0>(its_subscription),
                std::get<1>(its_subscription), std::get<2>(its_subscription), ANY_EVENT);
    }
    ep_mgr_->remove_local(_client);
    {
        std::lock_guard<std::mutex> its_lock(local_services_mutex_);
        // Finally remove all services that are implemented by the client.
        std::set<std::pair<service_t, instance_t>> its_services;
        for (const auto& s : local_services_) {
            for (const auto& i : s.second) {
                if (std::get<2>(i.second) == _client) {
                    its_services.insert({ s.first, i.first });
                    host_->on_availability(s.first, i.first, availability_state_e::AS_UNAVAILABLE,
                            std::get<0>(i.second), std::get<1>(i.second));
                }
            }
        }

        for (auto& si : its_services) {
            local_services_[si.first].erase(si.second);
            if (local_services_[si.first].size() == 0)
                local_services_.erase(si.first);
        }

        // remove disconnected client from offer service history
        std::set<std::tuple<service_t, instance_t, client_t>> its_clients;
        for (const auto& s : local_services_history_) {
            for (const auto& i : s.second) {
                for (const auto& c : i.second) {
                    if (c == _client) {
                        its_clients.insert(std::make_tuple(s.first, i.first, c));
                    }
                }
            }
        }

        for (auto& sic : its_clients) {
            local_services_history_[std::get<0>(sic)][std::get<1>(sic)].erase(std::get<2>(sic));
            if (local_services_history_[std::get<0>(sic)][std::get<1>(sic)].size() == 0) {
                local_services_history_.erase(std::get<0>(sic));
            }
        }
    }
}

std::shared_ptr<event> routing_manager_base::find_event(service_t _service,
        instance_t _instance, event_t _event) const {
    std::lock_guard<std::mutex> its_lock(events_mutex_);
    std::shared_ptr<event> its_event;
    auto find_service = events_.find(_service);
    if (find_service != events_.end()) {
        auto find_instance = find_service->second.find(_instance);
        if (find_instance != find_service->second.end()) {
            auto find_event = find_instance->second.find(_event);
            if (find_event != find_instance->second.end()) {
                its_event = find_event->second;
            }
        }
    }
    return its_event;
}

std::set<std::shared_ptr<eventgroupinfo> >
routing_manager_base::find_eventgroups(
        service_t _service, instance_t _instance) const {

    std::set<std::shared_ptr<eventgroupinfo> > its_eventgroups;

    std::lock_guard<std::mutex> its_lock{eventgroups_mutex_};
    auto found_service = eventgroups_.find(_service);
    if (found_service != eventgroups_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            for (const auto &e : found_instance->second)
                its_eventgroups.insert(e.second);
        }
    }

    return its_eventgroups;
}

std::shared_ptr<eventgroupinfo> routing_manager_base::find_eventgroup(
        service_t _service, instance_t _instance,
        eventgroup_t _eventgroup) const {
    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);

    std::shared_ptr<eventgroupinfo> its_info(nullptr);
    auto found_service = eventgroups_.find(_service);
    if (found_service != eventgroups_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            auto found_eventgroup = found_instance->second.find(_eventgroup);
            if (found_eventgroup != found_instance->second.end()) {
                its_info = found_eventgroup->second;
                std::shared_ptr<serviceinfo> its_service_info
                    = find_service(_service, _instance);
                if (its_service_info) {
                    std::string its_multicast_address;
                    uint16_t its_multicast_port;
                    if (configuration_->get_multicast(_service, _instance,
                            _eventgroup,
                            its_multicast_address, its_multicast_port)) {
                        try {
                            its_info->set_multicast(
                                    boost::asio::ip::address::from_string(
                                            its_multicast_address),
                                    its_multicast_port);
                        }
                        catch (...) {
                            VSOMEIP_ERROR << "Eventgroup ["
                                << std::hex << std::setw(4) << std::setfill('0')
                                << _service << "." << _instance << "." << _eventgroup
                                << "] is configured as multicast, but no valid "
                                       "multicast address is configured!";
                        }
                    }

                    // LB: THIS IS STRANGE. A "FIND" - METHOD SHOULD NOT ADD INFORMATION...
                    its_info->set_major(its_service_info->get_major());
                    its_info->set_ttl(its_service_info->get_ttl());
                    its_info->set_threshold(configuration_->get_threshold(
                            _service, _instance, _eventgroup));
                }
            }
        }
    }
    return its_info;
}

void routing_manager_base::remove_eventgroup_info(service_t _service,
        instance_t _instance, eventgroup_t _eventgroup) {
    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    auto found_service = eventgroups_.find(_service);
    if (found_service != eventgroups_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            found_instance->second.erase(_eventgroup);
        }
    }
}

bool routing_manager_base::send_local_notification(client_t _client,
        const byte_t *_data, uint32_t _size, instance_t _instance,
        bool _reliable, uint8_t _status_check, bool _force) {
#ifdef USE_DLT
    bool has_local(false);
#endif
    (void)_client;
    bool has_remote(false);
    service_t its_service = bithelper::read_uint16_be(&_data[VSOMEIP_SERVICE_POS_MIN]);
    method_t its_method   = bithelper::read_uint16_be(&_data[VSOMEIP_METHOD_POS_MIN]);

    std::shared_ptr<event> its_event = find_event(its_service, _instance, its_method);
    if (its_event && !its_event->is_shadow()) {
        for (auto its_client : its_event->get_filtered_subscribers(_force)) {

            // local
            if (its_client == VSOMEIP_ROUTING_CLIENT) {
                has_remote = true;
                continue;
            }
#ifdef USE_DLT
            else {
                has_local = true;
            }
#endif

            std::shared_ptr<endpoint> its_local_target = ep_mgr_->find_local(its_client);
            if (its_local_target) {
                send_local(its_local_target, its_client, _data, _size, _instance, _reliable,
                           protocol::id_e::SEND_ID, _status_check);
            }
        }
    }
#ifdef USE_DLT
    // Trace the message if a local client but will _not_ be forwarded to the routing manager
    if (has_local && !has_remote) {
        trace::header its_header;
        if (its_header.prepare(nullptr, true, _instance))
            tc_->trace(its_header.data_, VSOMEIP_TRACE_HEADER_SIZE,
                    _data, _size);
    }
#endif
    return has_remote;
}

bool routing_manager_base::send_local(
        std::shared_ptr<endpoint> &_target, client_t _client,
        const byte_t *_data, uint32_t _size, instance_t _instance,
        bool _reliable, protocol::id_e _command, uint8_t _status_check) const {

    bool has_sent(false);

    protocol::send_command its_command(_command);
    its_command.set_client(get_client());
    its_command.set_instance(_instance);
    its_command.set_reliable(_reliable);
    its_command.set_status(_status_check);
    its_command.set_target(_client);
    its_command.set_message(std::vector<byte_t>(_data, _data + _size));

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);
    if (its_error == protocol::error_e::ERROR_OK) {
        has_sent = _target->send(&its_buffer[0], uint32_t(its_buffer.size()));
    }

    return has_sent;
}

bool routing_manager_base::insert_subscription(
        service_t _service, instance_t _instance, eventgroup_t _eventgroup,
        event_t _event, const std::shared_ptr<debounce_filter_impl_t> &_filter,
        client_t _client, std::set<event_t> *_already_subscribed_events) {

    bool is_inserted(false);
    if (_event != ANY_EVENT) { // subscribe to specific event
        std::shared_ptr<event> its_event = find_event(_service, _instance, _event);
        if (its_event) {
            is_inserted = its_event->add_subscriber(_eventgroup, _filter, _client,
                    host_->is_routing());
        } else {
            VSOMEIP_WARNING << "routing_manager_base::insert_subscription("
                << std::hex << std::setfill('0')
                << std::setw(4) << _client << "): ["
                << std::setw(4) << _service << "."
                << std::setw(4) << _instance << "."
                << std::setw(4) << _eventgroup << "."
                << std::setw(4) << _event << "]"
                << " received subscription for unknown (unrequested / "
                << "unoffered) event. Creating placeholder event holding "
                << "subscription until event is requested/offered.";
            is_inserted = create_placeholder_event_and_subscribe(_service,
                    _instance, _eventgroup, _event, _filter, _client);
        }
    } else { // subscribe to all events of the eventgroup
        std::shared_ptr<eventgroupinfo> its_eventgroup
            = find_eventgroup(_service, _instance, _eventgroup);
        bool create_place_holder(false);
        if (its_eventgroup) {
            std::set<std::shared_ptr<event>> its_events = its_eventgroup->get_events();
            if (!its_events.size()) {
                create_place_holder = true;
            } else {
                for (const auto &e : its_events) {
                    if (e->is_subscribed(_client)) {
                        // client is already subscribed to event from eventgroup
                        // this can happen if events are members of multiple
                        // eventgroups
                        _already_subscribed_events->insert(e->get_event());
                    }
                    is_inserted = e->add_subscriber(_eventgroup, _filter, _client,
                            host_->is_routing()) || is_inserted;
                }
            }
        } else {
            create_place_holder = true;
        }
        if (create_place_holder) {
            VSOMEIP_WARNING << "routing_manager_base::insert_subscription("
                << std::hex << std::setfill('0')
                << std::setw(4) << _client << "): ["
                << std::setw(4) << _service << "."
                << std::setw(4) << _instance << "."
                << std::setw(4) << _eventgroup << "."
                << std::setw(4) << _event << "]"
                << " received subscription for unknown (unrequested / "
                << "unoffered) eventgroup. Creating placeholder event holding "
                << "subscription until event is requested/offered.";
            is_inserted = create_placeholder_event_and_subscribe(_service,
                    _instance, _eventgroup, _event, _filter, _client);
        }
    }
    return is_inserted;
}

std::shared_ptr<serializer> routing_manager_base::get_serializer() {

    std::unique_lock<std::mutex> its_lock(serializer_mutex_);
    while (serializers_.empty()) {
        VSOMEIP_INFO << __func__ << ": Client "
                << std::hex << std::setw(4) << std::setfill('0')
                << get_client()
                << " has no available serializer. Waiting...";
        serializer_condition_.wait(its_lock, [this] { return !serializers_.empty(); } );
        VSOMEIP_INFO << __func__ << ": Client "
                        << std::hex << std::setw(4) << std::setfill('0')
                        << get_client()
                        << " now checking for available serializer.";
    }

    auto its_serializer = serializers_.front();
    serializers_.pop();

    return its_serializer;
}

void routing_manager_base::put_serializer(
        const std::shared_ptr<serializer> &_serializer) {

    std::lock_guard<std::mutex> its_lock(serializer_mutex_);
    serializers_.push(_serializer);
    serializer_condition_.notify_one();
}

std::shared_ptr<deserializer> routing_manager_base::get_deserializer() {

    std::unique_lock<std::mutex> its_lock(deserializer_mutex_);
    while (deserializers_.empty()) {
        VSOMEIP_INFO << std::hex << "client " << get_client() <<
                "routing_manager_base::get_deserializer ~> all in use!";
        deserializer_condition_.wait(its_lock, [this] { return !deserializers_.empty(); });
        VSOMEIP_INFO << std::hex << "client " << get_client() <<
                        "routing_manager_base::get_deserializer ~> wait finished!";
    }

    auto its_deserializer = deserializers_.front();
    deserializers_.pop();

    return its_deserializer;
}

void routing_manager_base::put_deserializer(
        const std::shared_ptr<deserializer> &_deserializer) {

    std::lock_guard<std::mutex> its_lock(deserializer_mutex_);
    deserializers_.push(_deserializer);
    deserializer_condition_.notify_one();
}

void routing_manager_base::send_pending_subscriptions(service_t _service,
        instance_t _instance, major_version_t _major) {
    for (auto &ps : pending_subscriptions_) {
        if (ps.service_ == _service &&
                ps.instance_ == _instance && ps.major_ == _major) {
            send_subscribe(get_client(), ps.service_, ps.instance_,
                    ps.eventgroup_, ps.major_, ps.event_, ps.filter_);
        }
    }
}

void routing_manager_base::remove_pending_subscription(service_t _service,
        instance_t _instance, eventgroup_t _eventgroup, event_t _event) {
    if (_eventgroup == 0xFFFF) {
        for (auto it = pending_subscriptions_.begin();
                it != pending_subscriptions_.end();) {
            if (it->service_ == _service
                    && it->instance_ == _instance) {
                it = pending_subscriptions_.erase(it);
            } else {
                it++;
            }
        }
    } else if (_event == ANY_EVENT) {
        for (auto it = pending_subscriptions_.begin();
                it != pending_subscriptions_.end();) {
            if (it->service_ == _service
                    && it->instance_ == _instance
                    && it->eventgroup_ == _eventgroup) {
                it = pending_subscriptions_.erase(it);
            } else {
                it++;
            }
        }
    } else {
        for (auto it = pending_subscriptions_.begin();
                it != pending_subscriptions_.end();) {
            if (it->service_ == _service
                    && it->instance_ == _instance
                    && it->eventgroup_ == _eventgroup
                    && it->event_ == _event) {
                it = pending_subscriptions_.erase(it);
                break;
            } else {
                it++;
            }
        }
    }
}

std::set<std::tuple<service_t, instance_t, eventgroup_t>>
routing_manager_base::get_subscriptions(const client_t _client) {
    std::set<std::tuple<service_t, instance_t, eventgroup_t>> result;
    std::lock_guard<std::mutex> its_lock(events_mutex_);
    for (const auto& its_service : events_) {
        for (const auto& its_instance : its_service.second) {
            for (const auto& its_event : its_instance.second) {
                auto its_eventgroups = its_event.second->get_eventgroups(_client);
                for (const auto& e : its_eventgroups) {
                    result.insert(std::make_tuple(
                                    its_service.first,
                                    its_instance.first,
                                    e));
                }
            }
        }
    }
    return result;
}


void routing_manager_base::clear_shadow_subscriptions(void) {
    std::lock_guard<std::mutex> its_lock(events_mutex_);
    for (const auto& its_service : events_) {
        for (const auto& its_instance : its_service.second) {
            for (const auto& its_event : its_instance.second) {
                if (its_event.second->is_shadow())
                    its_event.second->clear_subscribers();
            }
        }
    }
}

bool
routing_manager_base::get_guest(client_t _client,
        boost::asio::ip::address &_address, port_t &_port) const {

    std::lock_guard<std::mutex> its_lock(guests_mutex_);
    auto find_guest = guests_.find(_client);
    if (find_guest == guests_.end())
        return false;

    _address = find_guest->second.first;
    _port = find_guest->second.second;

    return true;
}

void
routing_manager_base::add_guest(client_t _client,
        const boost::asio::ip::address &_address, port_t _port) {

    std::lock_guard<std::mutex> its_lock(guests_mutex_);
    guests_[_client] = std::make_pair(_address, _port);
}

void
routing_manager_base::remove_guest(client_t _client) {

    std::lock_guard<std::mutex> its_lock(guests_mutex_);
    guests_.erase(_client);
}

void
routing_manager_base::remove_subscriptions(port_t _local_port,
        const boost::asio::ip::address &_remote_address,
        port_t _remote_port) {

    (void)_local_port;
    (void)_remote_address;
    (void)_remote_port;
    // dummy method to implement routing_host interface
}

routing_state_e
routing_manager_base::get_routing_state() {
    return routing_state_;
}

#ifdef VSOMEIP_ENABLE_COMPAT
void routing_manager_base::set_incoming_subscription_state(client_t _client, service_t _service, instance_t _instance,
        eventgroup_t _eventgroup, event_t _event, subscription_state_e _state) {
    std::lock_guard<std::recursive_mutex> its_lock(incoming_subscription_state_mutex_);
    incoming_subscription_state_[_client][_service][_instance][_eventgroup][_event] = _state;
}

subscription_state_e routing_manager_base::get_incoming_subscription_state(client_t _client,
        service_t _service, instance_t _instance,
        eventgroup_t _eventgroup, event_t _event) {
    std::lock_guard<std::recursive_mutex> its_lock(incoming_subscription_state_mutex_);
    const auto its_client = incoming_subscription_state_.find(_client);
    if (its_client != incoming_subscription_state_.end()) {
        const auto its_service = its_client->second.find(_service);
        if (its_service != its_client->second.end()) {
            const auto its_instance = its_service->second.find(_instance);
            if (its_instance != its_service->second.end()) {
                const auto its_group = its_instance->second.find(_eventgroup);
                if (its_group != its_instance->second.end()) {
                    const auto its_event = its_group->second.find(_event);
                    if (its_event != its_group->second.end()) {
                        return its_event->second;
                    }
                    // If a specific event was not found, check if there is a remote subscriber to ANY_EVENT
                    const auto its_any_event = its_group->second.find(ANY_EVENT);
                    if (its_any_event != its_group->second.end()) {
                        return its_any_event->second;
                    }
                }
            }
        }
    }
    return subscription_state_e::SUBSCRIPTION_NOT_ACKNOWLEDGED;
}

void routing_manager_base::erase_incoming_subscription_state(client_t _client, service_t _service, instance_t _instance,
        eventgroup_t _eventgroup, event_t _event) {
    std::lock_guard<std::recursive_mutex> its_lock(incoming_subscription_state_mutex_);
    const auto its_client = incoming_subscription_state_.find(_client);
    if (its_client != incoming_subscription_state_.end()) {
        const auto its_service = its_client->second.find(_service);
        if (its_service != its_client->second.end()) {
            const auto its_instance = its_service->second.find(_instance);
            if (its_instance != its_service->second.end()) {
                const auto its_group = its_instance->second.find(_eventgroup);
                if (its_group != its_instance->second.end()) {
                    const auto its_event = its_group->second.find(_event);
                    if (its_event != its_group->second.end()) {
                        its_group->second.erase(_event);
                        if (its_group->second.empty()) {
                            its_instance->second.erase(its_group);
                            if (its_instance->second.empty()) {
                                its_service->second.erase(its_instance);
                                if (its_service->second.empty()) {
                                    its_client->second.erase(its_service);
                                    if (its_client->second.empty()) {
                                        incoming_subscription_state_.erase(its_client);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
#endif

} // namespace vsomeip_v3
