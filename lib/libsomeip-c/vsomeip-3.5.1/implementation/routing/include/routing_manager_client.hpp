// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_ROUTING_MANAGER_CLIENT_HPP
#define VSOMEIP_V3_ROUTING_MANAGER_CLIENT_HPP

#include <map>
#include <mutex>
#include <atomic>
#include <tuple>

#include <boost/asio/steady_timer.hpp>

#include <vsomeip/enumeration_types.hpp>
#include <vsomeip/handler.hpp>

#include "routing_manager_base.hpp"
#include "types.hpp"
#include "../../protocol/include/protocol.hpp"

namespace vsomeip_v3 {

class configuration;
class event;
#ifdef __linux__
class netlink_connector;
#endif
class routing_manager_host;

namespace protocol {
    class offered_services_response_command;
    class update_security_credentials_command;
}

class routing_manager_client
        : public routing_manager_base {
public:
    routing_manager_client(routing_manager_host *_host, bool _client_side_logging,
        const std::set<std::tuple<service_t, instance_t> > & _client_side_logging_filter);
    virtual ~routing_manager_client();

    void init();
    void start();
    void stop();

    std::shared_ptr<configuration> get_configuration() const;
    std::string get_env(client_t _client) const;
    std::string get_env_unlocked(client_t _client) const;

    bool offer_service(client_t _client,
            service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor);

    void stop_offer_service(client_t _client,
            service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor);

    void request_service(client_t _client,
            service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor);

    void release_service(client_t _client,
            service_t _service, instance_t _instance);

    void subscribe(client_t _client, const vsomeip_sec_client_t *_sec_client,
            service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, major_version_t _major,
            event_t _event, const std::shared_ptr<debounce_filter_impl_t> &_filter);

    void unsubscribe(client_t _client, const vsomeip_sec_client_t *_sec_client,
            service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, event_t _event);

    bool send(client_t _client, const byte_t *_data, uint32_t _size,
            instance_t _instance, bool _reliable,
            client_t _bound_client, const vsomeip_sec_client_t *_sec_client,
            uint8_t _status_check, bool _sent_from_remote,
            bool _force);

    bool send_to(const client_t _client,
            const std::shared_ptr<endpoint_definition> &_target,
            std::shared_ptr<message> _message);

    bool send_to(const std::shared_ptr<endpoint_definition> &_target,
            const byte_t *_data, uint32_t _size, instance_t _instance);

    void register_event(client_t _client,
            service_t _service, instance_t _instance,
            event_t _notifier,
            const std::set<eventgroup_t> &_eventgroups,
            const event_type_e _type,
            reliability_type_e _reliability,
            std::chrono::milliseconds _cycle, bool _change_resets_cycle,
            bool _update_on_change,
            epsilon_change_func_t _epsilon_change_func,
            bool _is_provided, bool _is_shadow, bool _is_cache_placeholder);

    void unregister_event(client_t _client, service_t _service,
            instance_t _instance, event_t _notifier, bool _is_provided);

    void on_connect(const std::shared_ptr<endpoint>& _endpoint);
    void on_disconnect(const std::shared_ptr<endpoint>& _endpoint);
    void on_message(const byte_t *_data, length_t _size, endpoint *_receiver,
            bool _is_multicast,
            client_t _bound_client, const vsomeip_sec_client_t *_sec_client,
            const boost::asio::ip::address &_remote_address,
            std::uint16_t _remote_port);

    void on_routing_info(const byte_t *_data, uint32_t _size);

    void register_client_error_handler(client_t _client,
            const std::shared_ptr<endpoint> &_endpoint);
    void handle_client_error(client_t _client);

    void on_offered_services_info(protocol::offered_services_response_command &_command);

    void send_get_offered_services_info(client_t _client, offer_type_e _offer_type);

private:
    void assign_client();
    void register_application();
    void deregister_application();

    void reconnect(const std::map<client_t, std::string> &_clients);

    void send_pong() const;

    void send_offer_service(client_t _client, service_t _service,
            instance_t _instance, major_version_t _major,
            minor_version_t _minor);

    void send_release_service(client_t _client,
            service_t _service, instance_t _instance);

    void send_pending_event_registrations(client_t _client);

    void send_register_event(client_t _client,
            service_t _service, instance_t _instance,
            event_t _notifier,
            const std::set<eventgroup_t> &_eventgroups,
            const event_type_e _type, reliability_type_e _reliability,
            bool _is_provided, bool _is_cyclic);

    void send_subscribe(client_t _client,
            service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, major_version_t _major,
            event_t _event, const std::shared_ptr<debounce_filter_impl_t> &_filter);

    void send_subscribe_nack(client_t _subscriber, service_t _service,
            instance_t _instance, eventgroup_t _eventgroup, event_t _event,
            remote_subscription_id_t _id);

    void send_subscribe_ack(client_t _subscriber, service_t _service,
            instance_t _instance, eventgroup_t _eventgroup, event_t _event,
            remote_subscription_id_t _id);

    bool is_field(service_t _service, instance_t _instance,
            event_t _event) const;

    void on_subscribe_nack(client_t _client, service_t _service,
            instance_t _instance, eventgroup_t _eventgroup, event_t _event);

    void on_subscribe_ack(client_t _client, service_t _service,
            instance_t _instance, eventgroup_t _eventgroup, event_t _event);

    void cache_event_payload(const std::shared_ptr<message> &_message);

    void on_stop_offer_service(service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor);

    void send_pending_commands();

    void init_receiver();

    void notify_remote_initially(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, const std::set<event_t> &_events_to_exclude);

    uint32_t get_remote_subscriber_count(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, bool _increment);
    void clear_remote_subscriber_count(service_t _service, instance_t _instance);

    void assign_client_timeout_cbk(boost::system::error_code const &_error);

    void register_application_timeout_cbk(boost::system::error_code const &_error);

    void send_registered_ack();

    void set_routing_state(routing_state_e _routing_state) {
        (void)_routing_state;
    };

    bool is_client_known(client_t _client);

    bool create_placeholder_event_and_subscribe(
            service_t _service, instance_t _instance, eventgroup_t _eventgroup,
            event_t _notifier, const std::shared_ptr<debounce_filter_impl_t> &_filter,
            client_t _client);

    void request_debounce_timeout_cbk(boost::system::error_code const &_error);

    void send_request_services(const std::set<protocol::service> &_requests);

    void send_unsubscribe_ack(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, remote_subscription_id_t _id);

    void resend_provided_event_registrations();
    void send_resend_provided_event_response(pending_remote_offer_id_t _id);

#ifndef VSOMEIP_DISABLE_SECURITY
    void send_update_security_policy_response(pending_security_update_id_t _update_id);
    void send_remove_security_policy_response(pending_security_update_id_t _update_id);
    void on_update_security_credentials(const protocol::update_security_credentials_command &_command);
#endif
    void on_client_assign_ack(const client_t &_client);

    port_t get_routing_port();

    void on_suspend();

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
    void on_net_state_change(bool _is_interface, const std::string &_name, bool _is_available);
#endif

private:

    enum class inner_state_type_e : std::uint8_t {
        ST_REGISTERED = 0x0,
        ST_DEREGISTERED = 0x1,
        ST_REGISTERING = 0x2,
        ST_ASSIGNING = 0x3,
        ST_ASSIGNED = 0x4
    };

    std::atomic_bool is_connected_;
    std::atomic_bool is_started_;
    std::atomic<inner_state_type_e> state_;

    std::shared_ptr<endpoint> sender_;  // --> stub
    std::shared_ptr<endpoint> receiver_;  // --> from everybody

    std::set<protocol::service> pending_offers_;
    std::set<protocol::service> requests_;
    std::set<protocol::service> requests_to_debounce_;

    struct event_data_t {
        service_t service_;
        instance_t instance_;
        event_t notifier_;
        event_type_e type_;
        reliability_type_e reliability_;
        bool is_provided_;
        bool is_cyclic_;
        std::set<eventgroup_t> eventgroups_;

        bool operator<(const event_data_t &_other) const {
            return std::tie(service_, instance_, notifier_,
                    type_, reliability_, is_provided_, is_cyclic_, eventgroups_)
                    < std::tie(_other.service_, _other.instance_,
                            _other.notifier_, _other.type_, _other.reliability_,
                            _other.is_provided_, _other.is_cyclic_, _other.eventgroups_);
        }
    };
    std::set<event_data_t> pending_event_registrations_;

    std::map<client_t, std::set<subscription_data_t>> pending_incoming_subscriptions_;
    std::recursive_mutex incoming_subscriptions_mutex_;

    std::mutex state_mutex_;
    std::condition_variable state_condition_;

    std::map<service_t,
                std::map<instance_t, std::map<eventgroup_t, uint32_t > > > remote_subscriber_count_;
    std::mutex remote_subscriber_count_mutex_;

    mutable std::mutex sender_mutex_;

    boost::asio::steady_timer register_application_timer_;

    std::mutex request_timer_mutex_;
    boost::asio::steady_timer request_debounce_timer_;
    bool request_debounce_timer_running_;

    const bool client_side_logging_;
    const std::set<std::tuple<service_t, instance_t> > client_side_logging_filter_;

    std::mutex stop_mutex_;

#if defined(__linux__) || defined(ANDROID)
    std::shared_ptr<netlink_connector> local_link_connector_;
    bool is_local_link_available_;
#endif
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_ROUTING_MANAGER_CLIENT_HPP_
