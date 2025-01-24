// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_EVENT_IMPL_HPP_
#define VSOMEIP_V3_EVENT_IMPL_HPP_

#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <atomic>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/steady_timer.hpp>

#include <vsomeip/primitive_types.hpp>
#include <vsomeip/function_types.hpp>
#include <vsomeip/payload.hpp>


namespace vsomeip_v3 {


class endpoint;
class endpoint_definition;
class message;
class payload;
class routing_manager;

struct debounce_filter_impl_t;

class event
        : public std::enable_shared_from_this<event> {
public:
    event(routing_manager *_routing, bool _is_shadow = false);

    service_t get_service() const;
    void set_service(service_t _service);

    instance_t get_instance() const;
    void set_instance(instance_t _instance);

    major_version_t get_version() const;
    void set_version(major_version_t _major);

    event_t get_event() const;
    void set_event(event_t _event);

    std::shared_ptr<payload> get_payload() const;

    void set_payload(const std::shared_ptr<payload> &_payload,
            const client_t _client, bool _force);

    void set_payload(const std::shared_ptr<payload> &_payload,
            const client_t _client,
            const std::shared_ptr<endpoint_definition>& _target, bool _force);

    bool prepare_update_payload(const std::shared_ptr<payload> &_payload,
            bool _force);
    void update_payload();

    bool set_payload_notify_pending(const std::shared_ptr<payload> &_payload);

    void set_payload(const std::shared_ptr<payload> &_payload, bool _force);
    void unset_payload(bool _force = false);

    event_type_e get_type() const;
    void set_type(const event_type_e _type);

    reliability_type_e get_reliability() const;
    void set_reliability(const reliability_type_e _reliability);

    bool is_field() const;
    bool is_provided() const;
    void set_provided(bool _is_provided);

    bool is_set() const;

    // SIP_RPC_357
    void set_update_cycle(std::chrono::milliseconds &_cycle);
    void set_change_resets_cycle(bool _change_resets_cycle);

    // SIP_RPC_358
    void set_update_on_change(bool _is_active);

    // SIP_RPC_359 (epsilon change)
    void set_epsilon_change_function(
            const epsilon_change_func_t &_epsilon_change_func);

    std::set<eventgroup_t> get_eventgroups() const;
    std::set<eventgroup_t> get_eventgroups(client_t _client) const;
    void add_eventgroup(eventgroup_t _eventgroup);
    void set_eventgroups(const std::set<eventgroup_t> &_eventgroups);

    void notify_one(client_t _client,
            const std::shared_ptr<endpoint_definition> &_target);
    void notify_one(client_t _client, bool _force);


    bool add_subscriber(eventgroup_t _eventgroup,
            const std::shared_ptr<debounce_filter_impl_t> &_filter,
            client_t _client, bool _force);
    void remove_subscriber(eventgroup_t _eventgroup, client_t _client);
    bool has_subscriber(eventgroup_t _eventgroup, client_t _client);
    std::set<client_t> get_subscribers();
    std::set<client_t> get_filtered_subscribers(bool _force);
    std::set<client_t> update_and_get_filtered_subscribers(
            const std::shared_ptr<payload> &_payload, bool _force);
    VSOMEIP_EXPORT std::set<client_t> get_subscribers(eventgroup_t _eventgroup);
    void clear_subscribers();

    void add_ref(client_t _client, bool _is_provided);
    void remove_ref(client_t _client, bool _is_provided);
    bool has_ref();
    bool has_ref(client_t _client, bool _is_provided);

    bool is_shadow() const;
    void set_shadow(bool _shadow);

    bool is_cache_placeholder() const;
    void set_cache_placeholder(bool _is_cache_place_holder);

    bool is_subscribed(client_t _client);

    void remove_pending(const std::shared_ptr<endpoint_definition> &_target);

    void set_session();

private:
    void update_cbk(boost::system::error_code const &_error);
    void notify(bool _force);
    void notify(client_t _client,
            const std::shared_ptr<endpoint_definition> &_target);

    void start_cycle();
    void stop_cycle();

    bool has_changed(const std::shared_ptr<payload> &_lhs,
            const std::shared_ptr<payload> &_rhs) const;

    void notify_one_unlocked(client_t _client, bool _force);
    void notify_one_unlocked(client_t _client,
            const std::shared_ptr<endpoint_definition> &_target);

    bool prepare_update_payload_unlocked(
            const std::shared_ptr<payload> &_payload, bool _force);
    void update_payload_unlocked();

    void get_pending_updates(const std::set<client_t> &_clients);

private:
    routing_manager *routing_;
    mutable std::mutex mutex_;

    std::shared_ptr<message> current_;
    std::shared_ptr<message> update_;

    std::atomic<event_type_e> type_;

    boost::asio::steady_timer cycle_timer_;
    std::chrono::milliseconds cycle_;

    std::atomic<bool> change_resets_cycle_;
    std::atomic<bool> is_updating_on_change_;

    mutable std::mutex eventgroups_mutex_;
    std::map<eventgroup_t, std::set<client_t> > eventgroups_;

    std::atomic<bool> is_set_;
    std::atomic<bool> is_provided_;

    std::mutex refs_mutex_;
    std::map<client_t, std::map<bool, uint32_t>> refs_;

    std::atomic<bool> is_shadow_;
    std::atomic<bool> is_cache_placeholder_;

    epsilon_change_func_t epsilon_change_func_;
    bool has_default_epsilon_change_func_;

    std::atomic<reliability_type_e> reliability_;

    std::set<std::shared_ptr<endpoint_definition> > pending_;

    std::mutex filters_mutex_;
    std::map<client_t, epsilon_change_func_t> filters_;
};

}  // namespace vsomeip_v3

#endif // VSOMEIP_V3_EVENT_IMPL_HPP_
