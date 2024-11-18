// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_ROUTING_MANAGER_IMPL_HPP_
#define VSOMEIP_V3_ROUTING_MANAGER_IMPL_HPP_

#include <map>
#include <memory>
#include <mutex>
#include <vector>
#include <list>
#include <unordered_set>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/steady_timer.hpp>

#include <vsomeip/primitive_types.hpp>
#include <vsomeip/handler.hpp>

#include "routing_manager_base.hpp"
#include "routing_manager_stub_host.hpp"
#include "types.hpp"

#include "../../endpoints/include/netlink_connector.hpp"
#include "../../service_discovery/include/service_discovery_host.hpp"
#include "../../endpoints/include/endpoint_manager_impl.hpp"


namespace vsomeip_v3 {

class configuration;
class deserializer;
class eventgroupinfo;
class routing_manager_host;
class routing_manager_stub;
class serializer;
class service_endpoint;

namespace sd {
class service_discovery;
} // namespace sd

namespace e2e {
class e2e_provider;
} // namespace e2e

class routing_manager_impl: public routing_manager_base,
        public routing_manager_stub_host,
        public sd::service_discovery_host {
public:
    routing_manager_impl(routing_manager_host *_host);
    ~routing_manager_impl();

    boost::asio::io_context &get_io();
    client_t get_client() const;
    const vsomeip_sec_client_t *get_sec_client() const;
    std::string get_client_host() const;
    void set_client_host(const std::string &_client_host);

    bool is_routing_manager() const;

    void init();
    void start();
    void stop();

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

    bool send(client_t _client, std::shared_ptr<message> _message,
            bool _force);

    bool send(client_t _client, const byte_t *_data, uint32_t _size,
            instance_t _instance, bool _reliable,
            client_t _bound_client, const vsomeip_sec_client_t *_sec_client,
            uint8_t _status_check, bool _sent_from_remote,
            bool _force);

    bool send_to(const client_t _client,
            const std::shared_ptr<endpoint_definition> &_target,
            std::shared_ptr<message> _message);

    bool send_to(const std::shared_ptr<endpoint_definition> &_target,
            const byte_t *_data, uint32_t _size,
            instance_t _instance);

    bool send_via_sd(const std::shared_ptr<endpoint_definition> &_target,
            const byte_t *_data, uint32_t _size, uint16_t _sd_port);

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

    void register_shadow_event(client_t _client,
            service_t _service, instance_t _instance,
            event_t _notifier,
            const std::set<eventgroup_t> &_eventgroups,
            event_type_e _type, reliability_type_e _reliability,
            bool _is_provided, bool _is_cyclic);

    void unregister_shadow_event(client_t _client, service_t _service,
            instance_t _instance, event_t _event,
            bool _is_provided);

    void notify_one(service_t _service, instance_t _instance,
            event_t _event, std::shared_ptr<payload> _payload,
            client_t _client, bool _force
#ifdef VSOMEIP_ENABLE_COMPAT
            , bool _remote_subscriber
#endif
            );

    void on_subscribe_ack(client_t _client, service_t _service,
                    instance_t _instance, eventgroup_t _eventgroup, event_t _event,
                    remote_subscription_id_t _id);

    void on_subscribe_nack(client_t _client, service_t _service,
                    instance_t _instance, eventgroup_t _eventgroup,
                    bool _remove, remote_subscription_id_t _id);


    // interface to stub
    inline std::shared_ptr<endpoint> find_local(client_t _client) {
        return ep_mgr_->find_local(_client);
    }
    inline std::shared_ptr<endpoint> find_or_create_local(
            client_t _client) {
        return ep_mgr_->find_or_create_local(_client);
    }

    std::shared_ptr<endpoint> find_or_create_remote_client(
            service_t _service, instance_t _instance, bool _reliable);

    void remove_local(client_t _client, bool _remove_uid);
    void on_stop_offer_service(client_t _client,
            service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor);

    void on_availability(service_t _service, instance_t _instance,
            availability_state_e _state,
            major_version_t _major, minor_version_t _minor);

    void on_pong(client_t _client);

    void on_subscribe_ack_with_multicast(
            service_t _service, instance_t _instance,
            const boost::asio::ip::address &_sender,
            const boost::asio::ip::address &_address, uint16_t _port);
    void on_unsubscribe_ack(client_t _client, service_t _service,
            instance_t _instance, eventgroup_t _eventgroup,
            remote_subscription_id_t _id);

    void on_connect(const std::shared_ptr<endpoint>& _endpoint);
    void on_disconnect(const std::shared_ptr<endpoint>& _endpoint);

    void on_message(const byte_t *_data, length_t _size, endpoint *_receiver,
            bool _is_multicast,
            client_t _bound_client, const vsomeip_sec_client_t *_sec_client,
            const boost::asio::ip::address &_remote_address,
            std::uint16_t _remote_port);
    bool on_message(service_t _service, instance_t _instance,
            const byte_t *_data, length_t _size, bool _reliable,
            client_t _bound_client, const vsomeip_sec_client_t *_sec_client,
            uint8_t _check_status = 0,
            bool _is_from_remote = false);
    void on_notification(client_t _client, service_t _service,
            instance_t _instance, const byte_t *_data, length_t _size,
            bool _notify_one);

    bool offer_service_remotely(service_t _service, instance_t _instance,
                                std::uint16_t _port, bool _reliable,
                                bool _magic_cookies_enabled);
    bool stop_offer_service_remotely(service_t _service, instance_t _instance,
                                     std::uint16_t _port, bool _reliable,
                                     bool _magic_cookies_enabled);

    // interface "service_discovery_host"
    std::shared_ptr<eventgroupinfo> find_eventgroup(service_t _service,
            instance_t _instance, eventgroup_t _eventgroup) const;
    services_t get_offered_services() const;
    std::shared_ptr<serviceinfo> get_offered_service(
            service_t _service, instance_t _instance) const;
    std::map<instance_t, std::shared_ptr<serviceinfo>> get_offered_service_instances(
                service_t _service) const;

    std::shared_ptr<endpoint> create_service_discovery_endpoint(const std::string &_address,
            uint16_t _port, bool _reliable);
    void init_routing_info();
    void add_routing_info(service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor, ttl_t _ttl,
            const boost::asio::ip::address &_reliable_address,
            uint16_t _reliable_port,
            const boost::asio::ip::address &_unreliable_address,
            uint16_t _unreliable_port);
    void del_routing_info(service_t _service, instance_t _instance,
            bool _has_reliable, bool _has_unreliable);
    void update_routing_info(std::chrono::milliseconds _elapsed);

    // Handle remote subscriptions / subscription acks
    void on_remote_subscribe(
            std::shared_ptr<remote_subscription> &_subscription,
            const remote_subscription_callback_t& _callback);
    void on_remote_unsubscribe(
            std::shared_ptr<remote_subscription> &_subscription);

    void expire_subscriptions(const boost::asio::ip::address &_address);
    void expire_subscriptions(const boost::asio::ip::address &_address,
                              std::uint16_t _port, bool _reliable);
    void expire_subscriptions(const boost::asio::ip::address &_address,
                              const configuration::port_range_t& _range,
                              bool _reliable);
    void expire_services(const boost::asio::ip::address &_address);
    void expire_services(const boost::asio::ip::address &_address,
                         std::uint16_t _port , bool _reliable);
    void expire_services(const boost::asio::ip::address &_address,
                         const configuration::port_range_t& _range , bool _reliable);

    std::chrono::steady_clock::time_point expire_subscriptions(bool _force);

    void register_client_error_handler(client_t _client,
            const std::shared_ptr<endpoint> &_endpoint);
    void handle_client_error(client_t _client);
    std::shared_ptr<endpoint_manager_impl> get_endpoint_manager() const;

    routing_state_e get_routing_state();
    void set_routing_state(routing_state_e _routing_state);

    void send_get_offered_services_info(client_t _client, offer_type_e _offer_type) {
        (void) _client;
        (void) _offer_type;
    }

    void send_initial_events(service_t _service, instance_t _instance,
                    eventgroup_t _eventgroup,
                    const std::shared_ptr<endpoint_definition> &_subscriber);

    void print_stub_status() const;

    void send_error(return_code_e _return_code, const byte_t *_data,
            length_t _size, instance_t _instance, bool _reliable,
            endpoint* const _receiver,
            const boost::asio::ip::address &_remote_address,
            std::uint16_t _remote_port);
    void service_endpoint_connected(service_t _service, instance_t _instance,
                                    major_version_t _major, minor_version_t _minor,
                                    const std::shared_ptr<endpoint>& _endpoint,
                                    bool _unreliable_only);
    void service_endpoint_disconnected(service_t _service, instance_t _instance,
                                    major_version_t _major, minor_version_t _minor,
                                    const std::shared_ptr<endpoint>& _endpoint);

    void register_sd_acceptance_handler(const sd_acceptance_handler_t& _handler) const;
    void register_reboot_notification_handler(const reboot_notification_handler_t& _handler) const;
    void register_routing_ready_handler(const routing_ready_handler_t& _handler);
    void register_routing_state_handler(const routing_state_handler_t& _handler);
    void sd_acceptance_enabled(const boost::asio::ip::address& _address,
                               const configuration::port_range_t& _range,
                               bool _reliable);

    void on_resend_provided_events_response(pending_remote_offer_id_t _id);
    client_t find_local_client(service_t _service, instance_t _instance);
    std::set<client_t> find_local_clients(service_t _service, instance_t _instance);
    bool is_subscribe_to_any_event_allowed(
            const vsomeip_sec_client_t *_sec_client, client_t _client,
            service_t _service, instance_t _instance, eventgroup_t _eventgroup);

#ifndef VSOMEIP_DISABLE_SECURITY
    bool update_security_policy_configuration(uid_t _uid, gid_t _gid,
            const std::shared_ptr<policy> &_policy,
            const std::shared_ptr<payload> &_payload,
            const security_update_handler_t &_handler);
    bool remove_security_policy_configuration(uid_t _uid, gid_t _gid,
            const security_update_handler_t &_handler);
#endif

    void add_known_client(client_t _client, const std::string &_client_host);

    void register_message_acceptance_handler(
            const message_acceptance_handler_t &_handler);

    void remove_subscriptions(port_t _local_port,
            const boost::asio::ip::address &_remote_address,
            port_t _remote_port);

private:
    bool offer_service(client_t _client,
            service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor,
            bool _must_queue);

    void stop_offer_service(client_t _client,
            service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor,
            bool _must_queue);

    bool deliver_message(const byte_t *_data, length_t _size,
            instance_t _instance, bool _reliable,
            client_t _bound_client, const vsomeip_sec_client_t *_sec_client,
            uint8_t _status_check = 0, bool _is_from_remote = false);
    bool deliver_notification(service_t _service, instance_t _instance,
            const byte_t *_data, length_t _length, bool _reliable,
            client_t _bound_client, const vsomeip_sec_client_t *_sec_client,
            uint8_t _status_check = 0, bool _is_from_remote = false);

    bool is_suppress_event(service_t _service, instance_t _instance,
            event_t _event) const;

    void init_service_info(service_t _service,
            instance_t _instance, bool _is_local_service);

    bool is_field(service_t _service, instance_t _instance,
            event_t _event) const;

    std::shared_ptr<endpoint> find_remote_client(service_t _service,
            instance_t _instance, bool _reliable, client_t _client);

    std::shared_ptr<endpoint> create_remote_client(service_t _service,
                instance_t _instance, bool _reliable, client_t _client);

    void clear_client_endpoints(service_t _service, instance_t _instance, bool _reliable);
    void clear_multicast_endpoints(service_t _service, instance_t _instance);

    std::set<eventgroup_t> get_subscribed_eventgroups(service_t _service,
            instance_t _instance);

    void clear_targets_and_pending_sub_from_eventgroups(service_t _service, instance_t _instance);
    void clear_remote_subscriber(service_t _service, instance_t _instance);

    return_code_e check_error(const byte_t *_data, length_t _size,
            instance_t _instance);

    bool supports_selective(service_t _service, instance_t _instance);

    void clear_remote_subscriber(service_t _service, instance_t _instance,
            client_t _client,
            const std::shared_ptr<endpoint_definition> &_target);

    void log_version_timer_cbk(boost::system::error_code const & _error);

    bool handle_local_offer_service(client_t _client, service_t _service,
            instance_t _instance, major_version_t _major,minor_version_t _minor);

    void send_subscribe(client_t _client,
            service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, major_version_t _major,
            event_t _event, const std::shared_ptr<debounce_filter_impl_t> &_filter);

    void on_net_interface_or_route_state_changed(bool _is_interface,
                                                 const std::string &_if,
                                                 bool _available);

    void start_ip_routing();

    void add_requested_service(client_t _client, service_t _service,
                       instance_t _instance, major_version_t _major,
                       minor_version_t _minor);
    void remove_requested_service(client_t _client, service_t _service,
                       instance_t _instance, major_version_t _major,
                       minor_version_t _minor);
    std::vector<std::pair<service_t, instance_t>> get_requested_services(client_t _client);
    std::set<client_t> get_requesters(service_t _service,
            instance_t _instance, major_version_t _major,
            minor_version_t _minor);
    std::set<client_t> get_requesters_unlocked(service_t _service,
            instance_t _instance, major_version_t _major,
            minor_version_t _minor);
    bool has_requester_unlocked(service_t _service,
            instance_t _instance, major_version_t _major,
            minor_version_t _minor);

    void call_sd_endpoint_connected(const boost::system::error_code &_error,
            service_t _service, instance_t _instance,
            const std::shared_ptr<endpoint> &_endpoint,
            std::shared_ptr<boost::asio::steady_timer> _timer);

    bool create_placeholder_event_and_subscribe(
            service_t _service, instance_t _instance, eventgroup_t _eventgroup,
            event_t _event, const std::shared_ptr<debounce_filter_impl_t> &_filter,
            client_t _client);

    void handle_subscription_state(client_t _client, service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, event_t _event);

    void memory_log_timer_cbk(boost::system::error_code const &_error);
    void status_log_timer_cbk(boost::system::error_code const &_error);

    void send_subscription(const client_t _offering_client,
            const service_t _service, const instance_t _instance,
            const eventgroup_t _eventgroup, const major_version_t _major,
            const std::set<client_t> &_clients,
            const remote_subscription_id_t _id);

    void send_unsubscription(client_t _offering_client,
            const service_t _service, const instance_t _instance,
            const eventgroup_t _eventgroup, const major_version_t _major,
            const std::set<client_t> &_removed,
            const remote_subscription_id_t _id);

    void send_expired_subscription(client_t _offering_client,
            const service_t _service, const instance_t _instance,
            const eventgroup_t _eventgroup,
            const std::set<client_t> &_removed,
            const remote_subscription_id_t _id);

    void cleanup_server_endpoint(service_t _service,
                                 const std::shared_ptr<endpoint>& _endpoint);

    pending_remote_offer_id_t pending_remote_offer_add(service_t _service,
                                                          instance_t _instance);
    std::pair<service_t, instance_t> pending_remote_offer_remove(
            pending_remote_offer_id_t _id);

    bool insert_offer_command(service_t _service, instance_t _instance, uint8_t _command,
                        client_t _client, major_version_t _major, minor_version_t _minor);
    bool erase_offer_command(service_t _service, instance_t _instance);

    std::string get_env(client_t _client) const;
    std::string get_env_unlocked(client_t _client) const;

    bool insert_event_statistics(service_t _service, instance_t _instance,
            method_t _method, length_t _length);
    void statistics_log_timer_cbk(boost::system::error_code const & _error);

    bool get_guest(client_t _client, boost::asio::ip::address &_address,
            port_t &_port) const;
    void add_guest(client_t _client, const boost::asio::ip::address &_address,
            port_t _port);
    void remove_guest(client_t _client);

    void send_suspend() const;

    void clear_local_services();

    bool is_acl_message_allowed(endpoint *_receiver,
            service_t _service, instance_t _instance,
            const boost::asio::ip::address &_remote_address) const;

#ifdef VSOMEIP_ENABLE_DEFAULT_EVENT_CACHING
    bool has_subscribed_eventgroup(
            service_t _service, instance_t _instance) const;
#endif // VSOMEIP_ENABLE_DEFAULT_EVENT_CACHING

private:
    std::shared_ptr<routing_manager_stub> stub_;
    std::shared_ptr<sd::service_discovery> discovery_;

    std::mutex requested_services_mutex_;
    std::map<service_t,
        std::map<instance_t,
            std::map<major_version_t,
                std::map<minor_version_t, std::set<client_t> >
            >
        >
    > requested_services_;

    std::mutex remote_subscribers_mutex_;
    std::map<service_t,
        std::map<instance_t,
            std::map<client_t,
                std::set<std::shared_ptr<endpoint_definition> >
            >
        >
    > remote_subscribers_;

    std::shared_ptr<serviceinfo> sd_info_;

    std::mutex version_log_timer_mutex_;
    boost::asio::steady_timer version_log_timer_;

    bool if_state_running_;
    bool sd_route_set_;
    bool routing_running_;
    std::mutex pending_sd_offers_mutex_;
    std::vector<std::pair<service_t, instance_t>> pending_sd_offers_;
#if defined(__linux__) || defined(ANDROID)
    std::shared_ptr<netlink_connector> netlink_connector_;
#endif

    std::mutex pending_offers_mutex_;
    // map to store pending offers.
    // 1st client id in tuple: client id of new offering application
    // 2nd client id in tuple: client id of previously/stored offering application
    std::map<service_t,
        std::map<instance_t,
                std::tuple<major_version_t, minor_version_t,
                            client_t, client_t>>> pending_offers_;

    std::mutex pending_subscription_mutex_;

    std::mutex remote_subscription_state_mutex_;
    std::map<std::tuple<service_t, instance_t, eventgroup_t, client_t>,
        subscription_state_e> remote_subscription_state_;

    std::shared_ptr<e2e::e2e_provider> e2e_provider_;

    std::mutex status_log_timer_mutex_;
    boost::asio::steady_timer status_log_timer_;

    std::mutex memory_log_timer_mutex_;
    boost::asio::steady_timer memory_log_timer_;

    std::shared_ptr<endpoint_manager_impl> ep_mgr_impl_;

    reboot_notification_handler_t reboot_notification_handler_;

    routing_ready_handler_t routing_ready_handler_;
    routing_state_handler_t routing_state_handler_;

    std::mutex pending_remote_offers_mutex_;
    pending_remote_offer_id_t pending_remote_offer_id_;
    std::map<pending_remote_offer_id_t, std::pair<service_t, instance_t>> pending_remote_offers_;

    std::chrono::steady_clock::time_point last_resume_;

    std::mutex offer_serialization_mutex_;
    std::map<std::pair<service_t, instance_t>, std::deque<std::tuple<uint8_t, client_t, major_version_t, minor_version_t>>> offer_commands_;

    std::mutex callback_counts_mutex_;
    std::map<uint32_t, uint16_t> callback_counts_;

    std::mutex statistics_log_timer_mutex_;
    boost::asio::steady_timer statistics_log_timer_;

    std::mutex message_statistics_mutex_;
    std::map<std::tuple<service_t, instance_t, method_t>,
        msg_statistic_t> message_statistics_;
    std::tuple<service_t, instance_t, method_t> message_to_discard_;
    uint32_t ignored_statistics_counter_;

    // synchronize update_remote_subscription() and send_(un)subscription()
    std::mutex update_remote_subscription_mutex_;

    message_acceptance_handler_t message_acceptance_handler_;
};

}  // namespace vsomeip_v3

#endif // VSOMEIP_V3_ROUTING_MANAGER_IMPL_HPP_
