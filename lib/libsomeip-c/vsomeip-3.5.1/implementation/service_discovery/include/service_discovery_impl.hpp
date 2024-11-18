// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SD_SERVICE_DISCOVERY_IMPL_
#define VSOMEIP_V3_SD_SERVICE_DISCOVERY_IMPL_

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <forward_list>
#include <atomic>
#include <tuple>

#include <boost/asio/steady_timer.hpp>

#include "../../configuration/include/configuration.hpp"
#include "../../endpoints/include/endpoint_definition.hpp"
#include "../../routing/include/types.hpp"
#include "../../routing/include/remote_subscription.hpp"

#include "service_discovery.hpp"
#include "ip_option_impl.hpp"
#include "ipv4_option_impl.hpp"
#include "ipv6_option_impl.hpp"
#include "deserializer.hpp"
#include "message_impl.hpp"

namespace vsomeip_v3 {

class endpoint;
class serializer;

namespace sd {

class entry_impl;
class eventgroupentry_impl;
class option_impl;
class remote_subscription_ack;
class request;
class serviceentry_impl;
class service_discovery_host;
class subscription;

typedef std::map<service_t,
            std::map<instance_t,
                std::shared_ptr<request>
            >
        > requests_t;

struct entry_data_t {
    std::shared_ptr<entry_impl> entry_;
    std::vector<std::shared_ptr<option_impl> > options_;
    std::shared_ptr<entry_impl> other_;
};

class service_discovery_impl: public service_discovery,
        public std::enable_shared_from_this<service_discovery_impl> {
public:
    service_discovery_impl(service_discovery_host *_host,
                           const std::shared_ptr<configuration>& _configuration);
    virtual ~service_discovery_impl();

    boost::asio::io_context &get_io();
    std::recursive_mutex& get_subscribed_mutex();

    void init();
    void start();
    void stop();

    void request_service(service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor, ttl_t _ttl);
    void release_service(service_t _service, instance_t _instance);

    void subscribe(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, major_version_t _major, ttl_t _ttl,
            client_t _client, const std::shared_ptr<eventgroupinfo>& _info);
    void unsubscribe(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, client_t _client);
    void unsubscribe_all(service_t _service, instance_t _instance);
    void unsubscribe_all_on_suspend();
    void remove_subscriptions(service_t _service, instance_t _instance);

    bool send(bool _is_announcing);

    void on_message(const byte_t* _data, length_t _length, const boost::asio::ip::address& _sender,
                    bool _is_multicast);

    void
    sent_messages(const byte_t* _data, length_t _size,
                  const boost::asio::ip::address& _remote_address = boost::asio::ip::address());

    void on_endpoint_connected(
            service_t _service, instance_t _instance,
            const std::shared_ptr<endpoint> &_endpoint);

    void offer_service(const std::shared_ptr<serviceinfo> &_info);
    bool stop_offer_service(const std::shared_ptr<serviceinfo> &_info, bool _send);
    bool send_collected_stop_offers(const std::vector<std::shared_ptr<serviceinfo>> &_infos);

    void set_diagnosis_mode(const bool _activate);

    bool get_diagnosis_mode();


    void update_remote_subscription(
            const std::shared_ptr<remote_subscription> &_subscription);

    void register_sd_acceptance_handler(const sd_acceptance_handler_t &_handler);
    void register_reboot_notification_handler(
             const reboot_notification_handler_t &_handler);
private:
    std::pair<session_t, bool> get_session(const boost::asio::ip::address &_address);
    void increment_session(const boost::asio::ip::address &_address);

    bool is_reboot(const boost::asio::ip::address &_sender,
            bool _is_multicast, bool _reboot_flag, session_t _session);

    bool check_session_id_sequence(const boost::asio::ip::address &_sender,
                const bool _is_multicast, const session_t &_session,
                session_t &_missing_session);

    void insert_find_entries(std::vector<std::shared_ptr<message_impl> > &_messages,
                             const requests_t &_requests);
    void insert_offer_entries(std::vector<std::shared_ptr<message_impl> > &_messages,
                              const services_t &_services, bool _ignore_phase);
    void insert_offer_service(std::vector<std::shared_ptr<message_impl> > &_messages,
                              const std::shared_ptr<const serviceinfo> &_info);

    entry_data_t create_eventgroup_entry(
            service_t _service, instance_t _instance, eventgroup_t _eventgroup,
            const std::shared_ptr<subscription> &_subscription,
            reliability_type_e _offer_type);

    void insert_subscription_ack(
            const std::shared_ptr<remote_subscription_ack>& _acknowledgement,
            const std::shared_ptr<eventgroupinfo> &_info, ttl_t _ttl,
            const std::shared_ptr<endpoint_definition> &_target,
            const std::set<client_t> &_clients);

    typedef std::set<std::pair<bool, std::uint16_t>> expired_ports_t;
    struct sd_acceptance_state_t {
        explicit sd_acceptance_state_t(expired_ports_t& _expired_ports)
            : expired_ports_(_expired_ports),
              sd_acceptance_required_(false),
              accept_entries_(false) {
        }

        expired_ports_t& expired_ports_;
        bool sd_acceptance_required_;
        bool accept_entries_;
    };

    void process_serviceentry(std::shared_ptr<serviceentry_impl>& _entry,
                              const std::vector<std::shared_ptr<option_impl>>& _options,
                              bool _unicast_flag,
                              std::vector<std::shared_ptr<message_impl>>& _resubscribes,
                              bool _received_via_multicast,
                              const sd_acceptance_state_t& _sd_ac_state);
    void check_sent_offers(const message_impl::entries_t& _entries,
                           const boost::asio::ip::address& _remote_address) const;
    void process_offerservice_serviceentry(
            service_t _service, instance_t _instance, major_version_t _major,
            minor_version_t _minor, ttl_t _ttl, const boost::asio::ip::address& _reliable_address,
            uint16_t _reliable_port, const boost::asio::ip::address& _unreliable_address,
            uint16_t _unreliable_port, std::vector<std::shared_ptr<message_impl>>& _resubscribes,
            bool _received_via_multicast, const sd_acceptance_state_t& _sd_ac_state);
    void send_offer_service(
            const std::shared_ptr<const serviceinfo> &_info, service_t _service,
            instance_t _instance, major_version_t _major, minor_version_t _minor,
            bool _unicast_flag);

    void process_findservice_serviceentry(service_t _service,
            instance_t _instance,
            major_version_t _major,
            minor_version_t _minor,
            bool _unicast_flag);
    void process_eventgroupentry(
            std::shared_ptr<eventgroupentry_impl> &_entry,
            const std::vector<std::shared_ptr<option_impl> > &_options,
            std::shared_ptr<remote_subscription_ack> &_acknowledgement,
            const boost::asio::ip::address &_sender,
            bool _is_multicast,
            bool _is_stop_subscribe_subscribe, bool _force_initial_events,
            const sd_acceptance_state_t& _sd_ac_state);
    void handle_eventgroup_subscription(
            service_t _service, instance_t _instance, eventgroup_t _eventgroup,
            major_version_t _major, ttl_t _ttl, uint8_t _counter, uint16_t _reserved,
            const boost::asio::ip::address& _first_address, uint16_t _first_port,
            bool _is_first_reliable, const boost::asio::ip::address& _second_address,
            uint16_t _second_port, bool _is_second_reliable,
            std::shared_ptr<remote_subscription_ack>& _acknowledgement,
            bool _is_stop_subscribe_subscribe, bool _force_initial_events,
            const std::set<client_t>& _clients, const sd_acceptance_state_t& _sd_ac_state,
            const std::shared_ptr<eventgroupinfo>& _info, const boost::asio::ip::address& _sender);
    void handle_eventgroup_subscription_ack(service_t _service,
            instance_t _instance, eventgroup_t _eventgroup,
            major_version_t _major, ttl_t _ttl, uint8_t _counter,
            const std::set<client_t> &_clients,
            const boost::asio::ip::address &_sender,
            const boost::asio::ip::address &_address, uint16_t _port);
    void handle_eventgroup_subscription_nack(service_t _service,
            instance_t _instance, eventgroup_t _eventgroup, uint8_t _counter,
            const std::set<client_t> &_clients);

    bool send(const std::vector<std::shared_ptr<message_impl>> &_messages);
    bool serialize_and_send(
            const std::vector<std::shared_ptr<message_impl>> &_messages,
            const boost::asio::ip::address &_address);

    void update_acknowledgement(
            const std::shared_ptr<remote_subscription_ack> &_acknowledgement);

    bool is_tcp_connected(service_t _service,
            instance_t _instance,
            const std::shared_ptr<endpoint_definition>& its_endpoint);

    void start_ttl_timer(int _shift = 0);
    void stop_ttl_timer();

    void check_ttl(const boost::system::error_code &_error);

    void start_subscription_expiration_timer();
    void start_subscription_expiration_timer_unlocked();
    void stop_subscription_expiration_timer();
    void stop_subscription_expiration_timer_unlocked();
    void expire_subscriptions(const boost::system::error_code &_error);

    bool check_ipv4_address(const boost::asio::ip::address& its_address) const;

    bool check_static_header_fields(
            const std::shared_ptr<const message> &_message) const;
    bool check_layer_four_protocol(
            const std::shared_ptr<const ip_option_impl>& _ip_option) const;

    void get_subscription_endpoints(service_t _service, instance_t _instance,
            std::shared_ptr<endpoint>& _reliable,
            std::shared_ptr<endpoint>& _unreliable) const;
    void get_subscription_address(const std::shared_ptr<endpoint> &_reliable,
            const std::shared_ptr<endpoint> &_unreliable,
            boost::asio::ip::address &_address) const;

    void update_request(service_t _service, instance_t _instance);

    void start_offer_debounce_timer(bool _first_start);
    void on_offer_debounce_timer_expired(const boost::system::error_code &_error);


    void start_find_debounce_timer(bool _first_start);
    void on_find_debounce_timer_expired(const boost::system::error_code &_error);


    void on_repetition_phase_timer_expired(
            const boost::system::error_code &_error,
            const std::shared_ptr<boost::asio::steady_timer>& _timer,
            std::uint8_t _repetition, std::uint32_t _last_delay);
    void on_find_repetition_phase_timer_expired(
            const boost::system::error_code &_error,
            const std::shared_ptr<boost::asio::steady_timer>& _timer,
            std::uint8_t _repetition, std::uint32_t _last_delay);
    void move_offers_into_main_phase(
            const std::shared_ptr<boost::asio::steady_timer> &_timer);

    bool send_stop_offer(const std::shared_ptr<serviceinfo>& _info);

    void start_main_phase_timer();
    void on_main_phase_timer_expired(const boost::system::error_code &_error);
    void stop_main_phase_timer();


    void send_uni_or_multicast_offerservice(
            const std::shared_ptr<const serviceinfo> &_info,
            bool _unicast_flag);
    bool last_offer_shorter_half_offer_delay_ago();
    void send_unicast_offer_service(
            const std::shared_ptr<const serviceinfo> &_info);
    void send_multicast_offer_service(
            const std::shared_ptr<const serviceinfo>& _info);

    bool check_source_address(const boost::asio::ip::address &its_source_address) const;

    void update_subscription_expiration_timer(
            const std::vector<std::shared_ptr<message_impl> > &_messages);

    void remote_subscription_acknowledge(
            service_t _service, instance_t _instance, eventgroup_t _eventgroup,
            const std::shared_ptr<remote_subscription> &_subscription);

    bool check_stop_subscribe_subscribe(
            message_impl::entries_t::const_iterator _iter,
            message_impl::entries_t::const_iterator _end,
            const message_impl::options_t &_options) const;

    bool has_opposite(
            message_impl::entries_t::const_iterator _iter,
            message_impl::entries_t::const_iterator _end,
            const message_impl::options_t &_options) const;

    bool has_same(
            message_impl::entries_t::const_iterator _iter,
            message_impl::entries_t::const_iterator _end,
            const message_impl::options_t &_options) const;

    bool is_subscribed(
            const std::shared_ptr<eventgroupentry_impl> &_entry,
            const message_impl::options_t &_options) const;

    configuration::ttl_factor_t get_ttl_factor(
            service_t _service, instance_t _instance,
            const configuration::ttl_map_t& _ttl_map) const;
    void on_last_msg_received_timer_expired(const boost::system::error_code &_error);
    void stop_last_msg_received_timer();

    reliability_type_e get_remote_offer_type(
            service_t _service, instance_t _instance) const;
    reliability_type_e get_remote_offer_type(
            const std::shared_ptr<subscription> &_subscription) const;

    bool update_remote_offer_type(service_t _service, instance_t _instance,
                                  reliability_type_e _offer_type,
                                  const boost::asio::ip::address& _reliable_address,
                                  std::uint16_t _reliable_port,
                                  const boost::asio::ip::address& _unreliable_address,
                                  std::uint16_t _unreliable_port, bool _received_via_multicast);
    void remove_remote_offer_type(service_t _service, instance_t _instance,
                                  const boost::asio::ip::address &_reliable_address,
                                  std::uint16_t _reliable_port,
                                  const boost::asio::ip::address &_unreliable_address,
                                  std::uint16_t _unreliable_port);
    void remove_remote_offer_type_by_ip(const boost::asio::ip::address &_address);
    void remove_remote_offer_type_by_ip(const boost::asio::ip::address &_address,
                                        std::uint16_t _port, bool _reliable);

    // Returns true if the state changes from unicast -> multicast, false any of the other 3 cases
    bool set_offer_multicast_state(service_t _service, instance_t _instance,
                                   reliability_type_e _offer_type,
                                   const boost::asio::ip::address& _reliable_address,
                                   port_t _reliable_port,
                                   const boost::asio::ip::address& _unreliable_address,
                                   std::uint16_t _unreliable_port, bool _received_via_multicast);

    std::shared_ptr<subscription>
    create_subscription(major_version_t _major, ttl_t _ttl,
                        const std::shared_ptr<endpoint>& _reliable,
                        const std::shared_ptr<endpoint>& _unreliable,
                        const std::shared_ptr<eventgroupinfo>& _info) const;

    std::shared_ptr<remote_subscription> get_remote_subscription(
            const service_t _service, const instance_t _instance,
            const eventgroup_t _eventgroup);

    void send_subscription_ack(
            const std::shared_ptr<remote_subscription_ack> &_acknowledgement);

    std::shared_ptr<option_impl> create_ip_option(
            const boost::asio::ip::address &_address, uint16_t _port,
            bool _is_reliable) const;

    void send_subscription(const std::shared_ptr<subscription> &_subscription,
            const service_t _service, const instance_t _instance,
            const eventgroup_t _eventgroup, const client_t _client);

    void add_entry_data(std::vector<std::shared_ptr<message_impl>> &_messages,
            const entry_data_t &_data);

    void add_entry_data_to_remote_subscription_ack_msg(
            const std::shared_ptr<remote_subscription_ack>& _acknowledgement,
            const entry_data_t &_data);
    reliability_type_e get_eventgroup_reliability(
            service_t _service, instance_t _instance, eventgroup_t _eventgroup,
            const std::shared_ptr<subscription>& _subscription);
    void deserialize_data(const byte_t* _data, const length_t& _size,
                          std::shared_ptr<message_impl>& _message);

private:
    boost::asio::io_context &io_;
    service_discovery_host *host_;
    std::shared_ptr<configuration> configuration_;

    boost::asio::ip::address unicast_;
    uint16_t port_;
    bool reliable_;
    std::shared_ptr<endpoint> endpoint_;

    std::shared_ptr<serializer> serializer_;
    std::shared_ptr<deserializer> deserializer_;

    requests_t requested_;
    std::mutex requested_mutex_;
    std::map<service_t,
        std::map<instance_t,
            std::map<eventgroup_t,
                std::shared_ptr<subscription>
            >
        >
    > subscribed_;
    std::recursive_mutex subscribed_mutex_;

    std::mutex serialize_mutex_;
    std::mutex deserialize_mutex_;

    // Sessions
    std::map<boost::asio::ip::address, std::pair<session_t, bool> > sessions_sent_;
    std::map<boost::asio::ip::address,
        std::tuple<session_t, session_t, bool, bool> > sessions_received_;
    std::mutex sessions_received_mutex_;

    // Runtime
    std::weak_ptr<runtime> runtime_;

    // TTL handling for services offered by other hosts
    std::mutex ttl_timer_mutex_;
    boost::asio::steady_timer ttl_timer_;
    std::chrono::milliseconds ttl_timer_runtime_;
    ttl_t ttl_;

    // TTL handling for subscriptions done by other hosts
    std::mutex subscription_expiration_timer_mutex_;
    boost::asio::steady_timer subscription_expiration_timer_;
    std::chrono::steady_clock::time_point next_subscription_expiration_;

    uint32_t max_message_size_;

    std::chrono::milliseconds initial_delay_;
    std::chrono::milliseconds offer_debounce_time_;
    std::chrono::milliseconds repetitions_base_delay_;
    std::uint8_t repetitions_max_;
    std::chrono::milliseconds cyclic_offer_delay_;
    std::mutex offer_debounce_timer_mutex_;
    boost::asio::steady_timer offer_debounce_timer_;
    // this map is used to collect offers while for offer debouncing
    std::mutex collected_offers_mutex_;
    services_t collected_offers_;

    std::chrono::milliseconds find_debounce_time_;
    std::mutex find_debounce_timer_mutex_;
    boost::asio::steady_timer find_debounce_timer_;
    requests_t collected_finds_;

    // this map contains the offers and their timers currently in repetition phase
    std::mutex repetition_phase_timers_mutex_;
    std::map<std::shared_ptr<boost::asio::steady_timer>,
            services_t> repetition_phase_timers_;

    // this map contains the finds and their timers currently in repetition phase
    std::mutex find_repetition_phase_timers_mutex_;
    std::map<std::shared_ptr<boost::asio::steady_timer>,
            requests_t> find_repetition_phase_timers_;

    std::mutex main_phase_timer_mutex_;
    boost::asio::steady_timer main_phase_timer_;

    std::atomic<bool> is_suspended_;

    std::string sd_multicast_;
    boost::asio::ip::address sd_multicast_address_;

    boost::asio::ip::address current_remote_address_;

    std::atomic<bool> is_diagnosis_;

    std::mutex pending_remote_subscriptions_mutex_;
    std::map<std::shared_ptr<remote_subscription>,
        std::shared_ptr<remote_subscription_ack>
    > pending_remote_subscriptions_;
    std::mutex acknowledgement_mutex_;

    std::mutex response_mutex_;

    configuration::ttl_map_t ttl_factor_offers_;
    configuration::ttl_map_t ttl_factor_subscriptions_;

    std::mutex last_msg_received_timer_mutex_;
    boost::asio::steady_timer last_msg_received_timer_;
    std::chrono::milliseconds last_msg_received_timer_timeout_;

    mutable std::mutex remote_offer_types_mutex_;
    std::map<std::pair<service_t, instance_t>, reliability_type_e> remote_offer_types_;

    struct remote_offer_info_t {
        std::pair<service_t, instance_t> service_info;

        // The goal of this flag is to handle the SOMEIPSD_00577 requirement
        // To do so we will keep track of the last received offer for a given service+instance pair
        // The transition between unicast > multicast should be less strict in validations
        // and not trigger a [StopSubscribe][Subscribe]
        // It shall be mutable to allow the value to be updated within a std::set
        mutable bool offer_received_via_multicast;

        remote_offer_info_t(service_t _service, instance_t _instance,
                            bool _received_via_multicast = true) :
            service_info(std::make_pair(_service, _instance)),
            offer_received_via_multicast(_received_via_multicast) { }

        // Use the service_info pair as the key for unique values within a std::set
        bool operator<(const remote_offer_info_t& other) const {
            return service_info < other.service_info;
        }
    };

    std::map<boost::asio::ip::address,
             std::map<std::pair<bool, std::uint16_t>, std::set<remote_offer_info_t>>>
            remote_offers_by_ip_;

    reboot_notification_handler_t reboot_notification_handler_;
    sd_acceptance_handler_t sd_acceptance_handler_;

    std::mutex offer_mutex_;
    std::mutex check_ttl_mutex_;
};

}  // namespace sd
}  // namespace vsomeip_v3

#endif // VSOMEIP_V3_SD_SERVICE_DISCOVERY_IMPL_
