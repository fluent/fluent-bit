// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_ROUTING_MANAGER_
#define VSOMEIP_V3_ROUTING_MANAGER_

#include <memory>
#include <set>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <vsomeip/function_types.hpp>
#include <vsomeip/structured_types.hpp>
#include <vsomeip/message.hpp>
#include <vsomeip/handler.hpp>
#include <vsomeip/vsomeip_sec.h>

#include "types.hpp"

#include "../../configuration/include/debounce_filter_impl.hpp"
#ifdef ANDROID
#include "../../configuration/include/internal_android.hpp"
#else
#include "../../configuration/include/internal.hpp"
#endif // ANDROID

namespace vsomeip_v3 {

class endpoint;
class endpoint_definition;
class event;
class payload;
class security;

class routing_manager {
public:
    virtual ~routing_manager() {
    }

    virtual boost::asio::io_context &get_io() = 0;
    virtual client_t get_client() const = 0;
//    virtual void set_client(const client_t &_client) = 0;
    virtual session_t get_session(bool _is_request) = 0;

    virtual const vsomeip_sec_client_t *get_sec_client() const = 0;

    virtual void init() = 0;
    virtual void start() = 0;
    virtual void stop() = 0;

    virtual bool offer_service(client_t _client, service_t _service,
            instance_t _instance, major_version_t _major,
            minor_version_t _minor) = 0;

    virtual void stop_offer_service(client_t _client, service_t _service,
            instance_t _instance, major_version_t _major,
            minor_version_t _minor) = 0;

    virtual void request_service(client_t _client, service_t _service,
            instance_t _instance, major_version_t _major,
            minor_version_t _minor) = 0;

    virtual void release_service(client_t _client, service_t _service,
            instance_t _instance) = 0;

    virtual void subscribe(client_t _client, const vsomeip_sec_client_t *_sec_client,
            service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, major_version_t _major,
            event_t _event, const std::shared_ptr<debounce_filter_impl_t> &_filter) = 0;

    virtual void unsubscribe(client_t _client, const vsomeip_sec_client_t *_sec_client,
            service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, event_t _event) = 0;

    virtual bool send(client_t _client, std::shared_ptr<message> _message,
            bool _force) = 0;

    virtual bool send(client_t _client, const byte_t *_data, uint32_t _size,
            instance_t _instance, bool _reliable,
            client_t _bound_client = VSOMEIP_ROUTING_CLIENT,
            const vsomeip_sec_client_t *_sec_client = nullptr,
            uint8_t _status_check = 0,
            bool _sent_from_remote = false,
            bool _force = true) = 0;

    virtual bool send_to(const client_t _client,
            const std::shared_ptr<endpoint_definition> &_target,
            std::shared_ptr<message> _message) = 0;

    virtual bool send_to(const std::shared_ptr<endpoint_definition> &_target,
            const byte_t *_data, uint32_t _size, instance_t _instance) = 0;

    virtual void register_event(client_t _client,
            service_t _service, instance_t _instance,
            event_t _notifier,
            const std::set<eventgroup_t> &_eventgroups,
            const event_type_e _type,
            reliability_type_e _reliability,
            std::chrono::milliseconds _cycle, bool _change_resets_cycle,
            bool _update_on_change,
            epsilon_change_func_t _epsilon_change_func,
            bool _is_provided, bool _is_shadow = false,
            bool _is_cache_placeholder = false) = 0;

    virtual void unregister_event(client_t _client, service_t _service,
            instance_t _instance, event_t _event, bool _is_provided) = 0;

    virtual std::shared_ptr<event> find_event(service_t _service,
            instance_t _instance, event_t _event) const = 0;

    virtual std::set<std::shared_ptr<event>> find_events(service_t _service,
            instance_t _instance, eventgroup_t _eventgroup) const = 0;

    virtual void notify(service_t _service, instance_t _instance,
            event_t _event, std::shared_ptr<payload> _payload,
            bool _force) = 0;

    virtual void notify_one(service_t _service, instance_t _instance,
            event_t _event, std::shared_ptr<payload> _payload,
            client_t _client, bool _force
#ifdef VSOMEIP_ENABLE_COMPAT
            , bool _remote_subscriber
#endif
            ) = 0;

    virtual void set_routing_state(routing_state_e _routing_state) = 0;

    virtual void send_get_offered_services_info(client_t _client, offer_type_e _offer_type) = 0;

    virtual void debounce_timeout_update_cbk(const boost::system::error_code &_error, const std::shared_ptr<vsomeip_v3::event> &_event, client_t _client, const std::shared_ptr<debounce_filter_impl_t> &_filter) = 0;
    virtual void register_debounce(const std::shared_ptr<debounce_filter_impl_t> &_filter, client_t _client, const std::shared_ptr<vsomeip_v3::event> &_event) = 0;
    virtual void remove_debounce(client_t _client, event_t _event) = 0;
    virtual void update_debounce_clients(const std::set<client_t> &_clients, event_t _event) = 0;
};

}  // namespace vsomeip_v3

#endif // VSOMEIP_V3_ROUTING_MANAGER_
