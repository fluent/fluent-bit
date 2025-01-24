// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_ROUTING_MANAGER_STUB_HOST_
#define VSOMEIP_V3_ROUTING_MANAGER_STUB_HOST_

#include <boost/asio/io_context.hpp>
#include <vsomeip/handler.hpp>
#include <vsomeip/vsomeip_sec.h>
#include "types.hpp"

namespace vsomeip_v3 {

struct debounce_filter_impl_t;
class endpoint_manager_impl;

class routing_manager_stub_host {
public:
    virtual ~routing_manager_stub_host() {
    }

    virtual bool offer_service(client_t _client, service_t _service,
            instance_t _instance, major_version_t _major,
            minor_version_t _minor, bool _must_queue = true) = 0;

    virtual void stop_offer_service(client_t _client, service_t _service,
            instance_t _instance, major_version_t _major,
            minor_version_t _minor, bool _must_queue = true) = 0;

    virtual void request_service(client_t _client, service_t _service,
            instance_t _instance, major_version_t _major,
            minor_version_t _minor) = 0;

    virtual void release_service(client_t _client, service_t _service,
            instance_t _instance) = 0;

    virtual void register_shadow_event(client_t _client, service_t _service,
            instance_t _instance, event_t _notifier,
            const std::set<eventgroup_t> &_eventgroups, event_type_e _type,
            reliability_type_e _reliability, bool _is_provided,
            bool _is_cyclic) = 0;

    virtual void unregister_shadow_event(client_t _client, service_t _service,
            instance_t _instance, event_t _event, bool _is_provided) = 0;

    virtual void subscribe(client_t _client, const vsomeip_sec_client_t *_sec_client,
            service_t _service, instance_t _instance, eventgroup_t _eventgroup,
            major_version_t _major, event_t _event,
            const std::shared_ptr<debounce_filter_impl_t> &_filter) = 0;

    virtual void on_subscribe_ack(client_t _client, service_t _service,
            instance_t _instance, eventgroup_t _eventgroup, event_t _event,
            remote_subscription_id_t _subscription_id) = 0;

    virtual void on_subscribe_nack(client_t _client, service_t _service,
            instance_t _instance, eventgroup_t _eventgroup,
			bool _remove, remote_subscription_id_t _subscription_id) = 0;

    virtual void unsubscribe(client_t _client, const vsomeip_sec_client_t *_sec_client,
            service_t _service, instance_t _instance, eventgroup_t _eventgroup,
            event_t _event) = 0;

    virtual void on_unsubscribe_ack(client_t _client, service_t _service,
            instance_t _instance, eventgroup_t _eventgroup,
            remote_subscription_id_t _unsubscription_id) = 0;

    virtual bool on_message(service_t _service, instance_t _instance,
            const byte_t *_data, length_t _size, bool _reliable,
            client_t _bound_client, const vsomeip_sec_client_t *_sec_client,
            uint8_t _status_check = 0, bool _is_from_remote = false) = 0;

    virtual void on_notification(client_t _client, service_t _service,
            instance_t _instance, const byte_t *_data, length_t _size,
            bool _notify_one = false) = 0;

    virtual void on_stop_offer_service(client_t _client, service_t _service,
            instance_t _instance, major_version_t _major,
            minor_version_t _minor) = 0;

    virtual void on_availability(service_t _service, instance_t _instance,
            availability_state_e _state, major_version_t _major,
            minor_version_t _minor) = 0;

    virtual std::shared_ptr<endpoint> find_local(client_t _client) = 0;

    virtual std::shared_ptr<endpoint> find_or_create_local(
            client_t _client) = 0;
    virtual void remove_local(client_t _client, bool _remove_local) = 0;

    virtual boost::asio::io_context& get_io() = 0;
    virtual client_t get_client() const = 0;
    virtual const vsomeip_sec_client_t *get_sec_client() const = 0;

    virtual void on_pong(client_t _client) = 0;

    virtual void handle_client_error(client_t _client) = 0;

    virtual std::shared_ptr<endpoint_manager_impl> get_endpoint_manager() const = 0;

    virtual void on_resend_provided_events_response(
            pending_remote_offer_id_t _id) = 0;

    virtual client_t find_local_client(service_t _service,
            instance_t _instance) = 0;

    virtual std::set<client_t> find_local_clients(service_t _service,
            instance_t _instance) = 0;

    virtual bool is_subscribe_to_any_event_allowed(
            const vsomeip_sec_client_t *_sec_client,
            client_t _client, service_t _service, instance_t _instance,
            eventgroup_t _eventgroup) = 0;

    virtual void add_known_client(client_t _client,
            const std::string &_client_host) = 0;

    virtual void set_client_host(const std::string &_client_host) = 0;

    virtual bool get_guest(client_t _client,
            boost::asio::ip::address &_address, port_t &_port) const = 0;
    virtual void add_guest(client_t _client,
            const boost::asio::ip::address &_address, port_t _port) = 0;
    virtual void remove_guest(client_t _client) = 0;

    virtual void clear_local_services() = 0;

    virtual routing_state_e get_routing_state() = 0;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_ROUTING_MANAGER_STUB_HOST_
