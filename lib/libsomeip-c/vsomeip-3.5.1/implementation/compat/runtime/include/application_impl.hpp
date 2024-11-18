// Copyright (C) 2019 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_COMPAT_APPLICATION_IMPL_HPP_
#define VSOMEIP_COMPAT_APPLICATION_IMPL_HPP_

#include <map>
#include <mutex>

#include <compat/vsomeip/application.hpp>

namespace vsomeip_v3 {
class application;
} // namespace vsomeip_v3

namespace vsomeip {

class application_impl
        : public application {
public:
    application_impl(const std::string &_name);
    ~application_impl();

    const std::string & get_name() const;
    client_t get_client() const;

    void set_configuration(
            const std::shared_ptr<configuration> _configuration);

    bool init();
    void start();
    void stop();

    void offer_service(service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor);
    void stop_offer_service(service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor);

    void offer_event(service_t _service, instance_t _instance, event_t _event,
            const std::set<eventgroup_t> &_eventgroups, bool _is_field);
    void stop_offer_event(service_t _service, instance_t _instance,
            event_t _event);

    void request_service(service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor,
            bool _use_exclusive_proxy);
    void release_service(service_t _service, instance_t _instance);

    void request_event(service_t _service, instance_t _instance,
            event_t _event, const std::set<eventgroup_t> &_eventgroups,
            bool _is_field);
    void release_event(service_t _service, instance_t _instance,
            event_t _event);

    void subscribe(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, major_version_t _major,
            subscription_type_e _subscription_type,
            event_t _event);
    void unsubscribe(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup);

    bool is_available(service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor) const;

    void send(std::shared_ptr<message> _message, bool _flush);
    void notify(service_t _service, instance_t _instance,
                event_t _event, std::shared_ptr<payload> _payload) const;
    void notify_one(service_t _service, instance_t _instance,
                event_t _event, std::shared_ptr<payload> _payload,
                client_t _client) const;

    void register_state_handler(state_handler_t _handler);
    void unregister_state_handler();

    void register_message_handler(service_t _service,
            instance_t _instance, method_t _method,
            message_handler_t _handler);
    void unregister_message_handler(service_t _service,
            instance_t _instance, method_t _method);

    void register_availability_handler(service_t _service,
            instance_t _instance, availability_handler_t _handler,
            major_version_t _major, minor_version_t _minor);
    void unregister_availability_handler(service_t _service,
            instance_t _instance,
            major_version_t _major, minor_version_t _minor);

    void register_subscription_handler(service_t _service,
            instance_t _instance, eventgroup_t _eventgroup,
            subscription_handler_t _handler);
    void unregister_subscription_handler(service_t _service,
                instance_t _instance, eventgroup_t _eventgroup);

    void register_subscription_error_handler(service_t _service,
            instance_t _instance, eventgroup_t _eventgroup,
            error_handler_t _handler);
    void unregister_subscription_error_handler(service_t _service,
                instance_t _instance, eventgroup_t _eventgroup);

    void clear_all_handler();

    bool is_routing() const;

    void offer_event(service_t _service,
            instance_t _instance, event_t _event,
            const std::set<eventgroup_t> &_eventgroups,
            bool _is_field,
            std::chrono::milliseconds _cycle,
            bool _change_resets_cycle,
            const epsilon_change_func_t &_epsilon_change_func);

    void notify(service_t _service, instance_t _instance,
            event_t _event, std::shared_ptr<payload> _payload,
            bool _force) const;

    void notify_one(service_t _service, instance_t _instance,
            event_t _event, std::shared_ptr<payload> _payload,
            client_t _client, bool _force) const;

    bool are_available(available_t &_available,
            service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor) const;

    void notify(service_t _service, instance_t _instance,
            event_t _event, std::shared_ptr<payload> _payload,
            bool _force, bool _flush) const;

    void notify_one(service_t _service, instance_t _instance,
                event_t _event, std::shared_ptr<payload> _payload,
                client_t _client, bool _force, bool _flush) const;

    void set_routing_state(routing_state_e _routing_state);

    void unsubscribe(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, event_t _event);

    void register_subscription_status_handler(service_t _service,
            instance_t _instance, eventgroup_t _eventgroup, event_t _event,
            subscription_status_handler_t _handler);

    void register_subscription_status_handler(service_t _service,
            instance_t _instance, eventgroup_t _eventgroup, event_t _event,
            subscription_status_handler_t _handler, bool _is_selective);

    void get_offered_services_async(
            offer_type_e _offer_type, offered_services_handler_t _handler);

    void set_watchdog_handler(
            watchdog_handler_t _handler, std::chrono::seconds _interval);

    virtual void register_async_subscription_handler(
            service_t _service, instance_t _instance, eventgroup_t _eventgroup,
            async_subscription_handler_t _handler);

    virtual void set_offer_acceptance_required(
            ip_address_t _address, const std::string _path, bool _enable);

    virtual offer_acceptance_map_type_t get_offer_acceptance_required();

    virtual void register_offer_acceptance_handler(
            offer_acceptance_handler_t _handler);

    virtual void register_reboot_notification_handler(
            reboot_notification_handler_t _handler);

    virtual void register_routing_ready_handler(
            routing_ready_handler_t _handler);

    virtual void register_routing_state_handler(
            routing_state_handler_t _handler);

    virtual bool update_service_configuration(
            service_t _service, instance_t _instance,
            std::uint16_t _port, bool _reliable,
            bool _magic_cookies_enabled, bool _offer);

    virtual void update_security_policy_configuration(
            uint32_t _uid, uint32_t _gid,
            std::shared_ptr<policy> _policy, std::shared_ptr<payload> _payload,
            security_update_handler_t _handler);

    virtual void remove_security_policy_configuration(
            uint32_t _uid, uint32_t _gid, security_update_handler_t _handler);

private:
    bool is_selective_event(
            vsomeip::service_t _service, vsomeip::instance_t _instance,
            const std::set<vsomeip::eventgroup_t> &_eventgroups);

private:
    std::shared_ptr<vsomeip_v3::application> impl_;

    std::map<service_t,
        std::map<instance_t, std::set<eventgroup_t> > > eventgroups_;
    std::mutex eventgroups_mutex_;
};

} // namespace vsomeip

#endif // VSOMEIP_COMPAT_APPLICATION_IMPL_HPP_
