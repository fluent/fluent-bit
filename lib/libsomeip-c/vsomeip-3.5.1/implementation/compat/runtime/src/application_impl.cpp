// Copyright (C) 2019 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/application.hpp>
#include <vsomeip/runtime.hpp>
#include <compat/vsomeip/runtime.hpp>

#include <vsomeip/internal/logger.hpp>

#include "../include/application_impl.hpp"
#ifdef ANDROID
#    include "../../../configuration/include/internal_android.hpp"
#else
#    include "../../../configuration/include/internal.hpp"
#endif
#include "../../message/include/message_impl.hpp"
#include "../../message/include/payload_impl.hpp"

namespace vsomeip {

application_impl::application_impl(const std::string &_name) {

    impl_ = vsomeip_v3::runtime::get()->create_application(_name);
}

application_impl::~application_impl() {

    vsomeip::runtime::get()->remove_application(impl_->get_name());
}

const std::string &
application_impl::get_name() const {

    return impl_->get_name();
}

client_t
application_impl::get_client() const {

    return impl_->get_client();
}

void
application_impl::set_configuration(const std::shared_ptr<configuration> _configuration) {

    (void)_configuration;
    // Not implemented
}

bool
application_impl::init() {

    return impl_->init();
}

void
application_impl::start() {

    impl_->start();
}

void
application_impl::stop() {

    impl_->stop();
}

void
application_impl::offer_service(service_t _service, instance_t _instance,
        major_version_t _major, minor_version_t _minor) {

    impl_->offer_service(_service, _instance, _major, _minor);
}

void
application_impl::stop_offer_service(service_t _service, instance_t _instance,
        major_version_t _major, minor_version_t _minor) {

    impl_->stop_offer_service(_service, _instance, _major, _minor);
}

void
application_impl::offer_event(service_t _service, instance_t _instance,
        event_t _event, const std::set<eventgroup_t> &_eventgroups,
        bool _is_field) {

    // Set event type
    vsomeip_v3::event_type_e its_type(vsomeip_v3::event_type_e::ET_EVENT);
    if (_is_field)
        its_type = vsomeip_v3::event_type_e::ET_FIELD;
    else {
        // Find out whether the event is selective. Requires a preceding
        // call to "register_subscription_handler".
        // Note: The check can be done on the eventgroup(s) as selective
        // events own an exclusive eventgroup.
        const bool is_selective
            = is_selective_event(_service, _instance, _eventgroups);

        if (is_selective)
            its_type = vsomeip_v3::event_type_e::ET_SELECTIVE_EVENT;
    }

    impl_->offer_event(_service, _instance, _event, _eventgroups, its_type);
}

void
application_impl::stop_offer_event(service_t _service, instance_t _instance,
        event_t _event) {

    impl_->stop_offer_event(_service, _instance, _event);
}

void
application_impl::request_service(service_t _service, instance_t _instance,
        major_version_t _major, minor_version_t _minor,
        bool _use_exclusive_proxy) {

    (void)_use_exclusive_proxy;
    impl_->request_service(_service, _instance, _major, _minor);
}

void
application_impl::release_service(service_t _service, instance_t _instance) {

    impl_->release_service(_service, _instance);
}

void
application_impl::request_event(service_t _service, instance_t _instance,
        event_t _event, const std::set<eventgroup_t> &_eventgroups,
        bool _is_field) {

    const vsomeip_v3::event_type_e its_type = (_is_field) ?
            vsomeip_v3::event_type_e::ET_FIELD :
            vsomeip_v3::event_type_e::ET_EVENT;
    impl_->request_event(_service, _instance, _event, _eventgroups, its_type);
}

void
application_impl::release_event(service_t _service, instance_t _instance,
        event_t _event) {

    impl_->release_event(_service, _instance, _event);
}

void
application_impl::subscribe(service_t _service, instance_t _instance,
        eventgroup_t _eventgroup, major_version_t _major,
        subscription_type_e _subscription_type, event_t _event) {

    (void)_subscription_type; // unused in v3
    impl_->subscribe(_service, _instance, _eventgroup, _major, _event);
}

void
application_impl::unsubscribe(service_t _service, instance_t _instance,
        eventgroup_t _eventgroup) {

    impl_->unsubscribe(_service, _instance, _eventgroup);
}

bool
application_impl::is_available(service_t _service, instance_t _instance,
        major_version_t _major, minor_version_t _minor) const {

    return impl_->is_available(_service, _instance, _major, _minor);
}

void
application_impl::send(std::shared_ptr<message> _message, bool _flush = true) {

    (void)_flush; // unused in v3
    if (_message) {
        auto its_message = std::dynamic_pointer_cast<message_impl>(_message);
        impl_->send(its_message->get_impl());
    }
}

void
application_impl::notify(service_t _service, instance_t _instance,
            event_t _event, std::shared_ptr<payload> _payload) const {

    if (_payload) {
        auto its_payload = std::dynamic_pointer_cast<payload_impl>(_payload);
        impl_->notify(_service, _instance, _event, its_payload->get_impl());
    } else {
        impl_->notify(_service, _instance, _event, nullptr);
    }
}

void
application_impl::notify_one(service_t _service, instance_t _instance,
            event_t _event, std::shared_ptr<payload> _payload,
            client_t _client) const {

    if (_payload) {
        auto its_payload = std::dynamic_pointer_cast<payload_impl>(_payload);
        impl_->notify_one(_service, _instance, _event, its_payload->get_impl(), _client);
    } else {
        impl_->notify_one(_service, _instance, _event, nullptr, _client);
    }
}

void
application_impl::register_state_handler(state_handler_t _handler) {

    impl_->register_state_handler(
            [_handler](vsomeip_v3::state_type_e _state) {
                _handler(static_cast<vsomeip::state_type_e>(_state));
            }
    );
}

void
application_impl::unregister_state_handler() {

    impl_->unregister_state_handler();
}

void
application_impl::register_message_handler(
        service_t _service, instance_t _instance, method_t _method,
        message_handler_t _handler) {

    impl_->register_message_handler(_service, _instance, _method,
            [_handler](const std::shared_ptr<vsomeip_v3::message> &_message) {
                auto its_message = std::make_shared<message_impl>(_message);
                _handler(its_message);
            }
    );
}

void
application_impl::unregister_message_handler(
        service_t _service, instance_t _instance, method_t _method) {

    impl_->unregister_message_handler(_service, _instance, _method);
}

void
application_impl::register_availability_handler(
        service_t _service, instance_t _instance,
        availability_handler_t _handler,
        major_version_t _major, minor_version_t _minor) {

    impl_->register_availability_handler(_service, _instance, _handler,
            _major, _minor);
}

void
application_impl::unregister_availability_handler(
        service_t _service, instance_t _instance,
        major_version_t _major, minor_version_t _minor) {

    impl_->unregister_availability_handler(_service, _instance, _major, _minor);
}

void
application_impl::register_subscription_handler(
        service_t _service, instance_t _instance, eventgroup_t _eventgroup,
        subscription_handler_t _handler) {
    {
        std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
        eventgroups_[_service][_instance].insert(_eventgroup);
    }

    impl_->register_subscription_handler(_service, _instance, _eventgroup,
            [_handler](client_t _client, vsomeip::uid_t _uid,
                    vsomeip::gid_t _gid, bool _accepted){
                (void)_uid;
                (void)_gid;
                return _handler(_client, _accepted);
            }
    );
}

void
application_impl::unregister_subscription_handler(
        service_t _service, instance_t _instance, eventgroup_t _eventgroup) {

    impl_->unregister_subscription_handler(_service, _instance, _eventgroup);
}


// subscription_error_handlers were exclusively used for selective events.
// As selective events use an exclusive eventgroup, the event identifier
// itself is not needed and we can use a dummy.
#define ERROR_HANDLER_DUMMY_EVENT 0xFFFE

void
application_impl::register_subscription_error_handler(
        service_t _service, instance_t _instance, eventgroup_t _eventgroup,
        error_handler_t _handler) {

    impl_->register_subscription_status_handler(
            _service, _instance, _eventgroup, ERROR_HANDLER_DUMMY_EVENT,
            [_handler](service_t _service, instance_t _instance,
                       eventgroup_t _eventgroup, event_t _event,
                       uint16_t _error) {
                (void)_service;
                (void)_instance;
                (void)_eventgroup;
                (void)_event;

                _handler(_error);
            },
            true
    );
}

void
application_impl::unregister_subscription_error_handler(
        service_t _service, instance_t _instance, eventgroup_t _eventgroup) {

    impl_->unregister_subscription_status_handler(_service, _instance,
            _eventgroup, ERROR_HANDLER_DUMMY_EVENT);
}

void
application_impl::clear_all_handler() {

    impl_->clear_all_handler();
}

bool
application_impl::is_routing() const {

    return impl_->is_routing();
}

void
application_impl::offer_event(
        service_t _service, instance_t _instance, event_t _event,
        const std::set<eventgroup_t> &_eventgroups,
        bool _is_field,
        std::chrono::milliseconds _cycle,
        bool _change_resets_cycle,
        const epsilon_change_func_t &_epsilon_change_func) {

    // Set event type
    vsomeip_v3::event_type_e its_type(vsomeip_v3::event_type_e::ET_EVENT);
    if (_is_field)
        its_type = vsomeip_v3::event_type_e::ET_FIELD;
    else {
        // Find out whether the event is selective. Requires a preceding
        // call to "register_subscription_handler".
        // Note: The check can be done on the eventgroup(s) as selective
        // events own an exclusive eventgroup.
        const bool is_selective
            = is_selective_event(_service, _instance, _eventgroups);

        if (is_selective)
            its_type = vsomeip_v3::event_type_e::ET_SELECTIVE_EVENT;
    }

    impl_->offer_event(_service, _instance, _event, _eventgroups,
            its_type, _cycle, _change_resets_cycle, true,
            [_epsilon_change_func](
                    const std::shared_ptr<vsomeip_v3::payload> &_lhs,
                    const std::shared_ptr<vsomeip_v3::payload> &_rhs) {
                auto its_lhs = std::make_shared<payload_impl>(_lhs);
                auto its_rhs = std::make_shared<payload_impl>(_rhs);
                return _epsilon_change_func(its_lhs, its_rhs);
            }
    );
}

void
application_impl::notify(service_t _service, instance_t _instance,
        event_t _event, std::shared_ptr<payload> _payload, bool _force) const {

    if (_payload) {
        auto its_payload = std::dynamic_pointer_cast<payload_impl>(_payload);
        impl_->notify(_service, _instance, _event, its_payload->get_impl(),
                _force);
    } else {
        impl_->notify(_service, _instance, _event, nullptr, _force);
    }
}

void
application_impl::notify_one(service_t _service, instance_t _instance,
        event_t _event, std::shared_ptr<payload> _payload,
        client_t _client, bool _force) const {

    if (_payload) {
        auto its_payload = std::dynamic_pointer_cast<payload_impl>(_payload);
        impl_->notify_one(_service, _instance, _event, its_payload->get_impl(),
                _client, _force);
    } else {
        impl_->notify_one(_service, _instance, _event, nullptr, _client,
                _force);
    }
}

bool
application_impl::are_available(available_t &_available,
        service_t _service, instance_t _instance,
        major_version_t _major, minor_version_t _minor) const {

    return impl_->are_available(_available, _service, _instance, _major,
            _minor);
}

void
application_impl::notify(service_t _service, instance_t _instance,
        event_t _event, std::shared_ptr<payload> _payload,
        bool _force, bool _flush) const {

    (void)_flush; // unused in v3

    if (_payload) {
        auto its_payload = std::dynamic_pointer_cast<payload_impl>(_payload);
        impl_->notify(_service, _instance, _event, its_payload->get_impl(),
                _force);
    } else {
        impl_->notify(_service, _instance, _event, nullptr, _force);
    }
}

void
application_impl::notify_one(service_t _service, instance_t _instance,
            event_t _event, std::shared_ptr<payload> _payload,
            client_t _client, bool _force, bool _flush) const {

    (void)_flush; // unused in v3

    if (_payload) {
        auto its_payload = std::dynamic_pointer_cast<payload_impl>(_payload);
        impl_->notify_one(_service, _instance, _event, its_payload->get_impl(),
                _client, _force);
    } else {
        impl_->notify_one(_service, _instance, _event, nullptr, _client,
                _force);
    }
}

void
application_impl::set_routing_state(routing_state_e _routing_state) {

    impl_->set_routing_state(
            static_cast<vsomeip_v3::routing_state_e>(_routing_state));
}

void
application_impl::unsubscribe(service_t _service, instance_t _instance,
        eventgroup_t _eventgroup, event_t _event) {

    impl_->unsubscribe(_service, _instance, _eventgroup, _event);
}

void
application_impl::register_subscription_status_handler(service_t _service,
        instance_t _instance, eventgroup_t _eventgroup, event_t _event,
        subscription_status_handler_t _handler) {

    register_subscription_status_handler(_service, _instance,
            _eventgroup, _event, _handler, false);
}

void
application_impl::register_subscription_status_handler(service_t _service,
        instance_t _instance, eventgroup_t _eventgroup, event_t _event,
        subscription_status_handler_t _handler, bool _is_selective) {
    if (_is_selective) {
        std::set<vsomeip::eventgroup_t> its_eventgroups;
        its_eventgroups.insert(_eventgroup);
        // An application may call "register_event" before
        // "register_subscription_status_handler". While the call to
        // "register_subscription_status_handler" contains the information
        // whether an event is selective, the call to "register_event" does
        // not. Therefore, we re-register the event with correct event type
        // here.
        impl_->request_event(_service, _instance, _event, its_eventgroups,
                vsomeip_v3::event_type_e::ET_SELECTIVE_EVENT);
    }

    impl_->register_subscription_status_handler(_service, _instance,
            _eventgroup, _event,
            [_handler](const vsomeip_v3::service_t _service,
                       const vsomeip_v3::instance_t _instance,
                       const vsomeip_v3::eventgroup_t _eventgroup,
                       const vsomeip_v3::event_t _event,
                       const uint16_t _error) {

                if (_handler)
                    _handler(_service, _instance, _eventgroup, _event, _error);
            },
            _is_selective);
}

void
application_impl::get_offered_services_async(
        offer_type_e _offer_type, offered_services_handler_t _handler) {

    impl_->get_offered_services_async(
            static_cast<vsomeip_v3::offer_type_e>(_offer_type), _handler);
}

void
application_impl::set_watchdog_handler(
        watchdog_handler_t _handler, std::chrono::seconds _interval) {

    impl_->set_watchdog_handler(_handler, _interval);
}

void
application_impl::register_async_subscription_handler(
        service_t _service, instance_t _instance, eventgroup_t _eventgroup,
        async_subscription_handler_t _handler) {

    {
        std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
        eventgroups_[_service][_instance].insert(_eventgroup);
    }
    impl_->register_async_subscription_handler(_service, _instance,
            _eventgroup, [_handler](client_t _client,
                    vsomeip::uid_t _uid, vsomeip::gid_t _gid, bool _accepted,
                    std::function<void(const bool)> _handler2) {
                (void)_uid;
                (void)_gid;
                _handler(_client, _accepted, _handler2);
            });
}

////////////////////////////////////////////////////////////////////////////////
// The following methods are not implemented as they should only be used by
// plugin implementations that are not intended to run in compatibility mode
////////////////////////////////////////////////////////////////////////////////
void
application_impl::set_offer_acceptance_required(
        ip_address_t _address, const std::string _path, bool _enable) {

    (void)_address;
    (void)_path;
    (void)_enable;

    VSOMEIP_ERROR << __func__ << ": Must not be called from compatibility layer.";
}

vsomeip::application::offer_acceptance_map_type_t
application_impl::get_offer_acceptance_required() {

    VSOMEIP_ERROR << __func__ << ": Must not be called from compatibility layer.";
    return vsomeip::application::offer_acceptance_map_type_t();
}

void
application_impl::register_offer_acceptance_handler(
        offer_acceptance_handler_t _handler) {

    (void)_handler;
    VSOMEIP_ERROR << __func__ << ": Must not be called from compatibility layer.";
}

void
application_impl::register_reboot_notification_handler(
        reboot_notification_handler_t _handler) {

    (void)_handler;
    VSOMEIP_ERROR << __func__ << ": Must not be called from compatibility layer.";
}

void
application_impl::register_routing_ready_handler(
        routing_ready_handler_t _handler) {

    (void)_handler;
    VSOMEIP_ERROR << __func__ << ": Must not be called from compatibility layer.";
}

void
application_impl::register_routing_state_handler(
        routing_state_handler_t _handler) {

    (void)_handler;
    VSOMEIP_ERROR << __func__ << ": Must not be called from compatibility layer.";
}

bool
application_impl::update_service_configuration(
        service_t _service, instance_t _instance,
        std::uint16_t _port, bool _reliable,
        bool _magic_cookies_enabled, bool _offer) {

    (void)_service;
    (void)_instance;
    (void)_port;
    (void)_reliable;
    (void)_magic_cookies_enabled;
    (void)_offer;

    VSOMEIP_ERROR << __func__ << ": Must not be called from compatibility layer.";
    return false;
}

void
application_impl::update_security_policy_configuration(
        uint32_t _uid, uint32_t _gid,
        std::shared_ptr<policy> _policy, std::shared_ptr<payload> _payload,
        security_update_handler_t _handler) {

    (void)_uid;
    (void)_gid;
    (void)_policy;
    (void)_payload;
    (void)_handler;

    VSOMEIP_ERROR << __func__ << ": Must not be called from compatibility layer.";
}

void
application_impl::remove_security_policy_configuration(
        uint32_t _uid, uint32_t _gid, security_update_handler_t _handler) {

    (void)_uid;
    (void)_gid;
    (void)_handler;

    VSOMEIP_ERROR << __func__ << ": Must not be called from compatibility layer.";
}

////////////////////////////////////////////////////////////////////////////////
// Private helper
////////////////////////////////////////////////////////////////////////////////

bool
application_impl::is_selective_event(
        vsomeip::service_t _service, vsomeip::instance_t _instance,
        const std::set<vsomeip::eventgroup_t> &_eventgroups) {

    bool is_selective(false);

    std::lock_guard<std::mutex> its_events_lock(eventgroups_mutex_);
    const auto its_service = eventgroups_.find(_service);
    if (its_service != eventgroups_.end()) {
        const auto its_instance = its_service->second.find(_instance);
        if (its_instance != its_service->second.end()) {
            for (const auto eg : _eventgroups) {
                const auto its_egrp = its_instance->second.find(eg);
                if (its_egrp != its_instance->second.end()) {
                    is_selective = true;
                    break;
                }
            }
        }
    }

    return is_selective;
}

} // namespace vsomeip
