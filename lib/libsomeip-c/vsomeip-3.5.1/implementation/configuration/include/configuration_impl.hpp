// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_CFG_CONFIGURATION_IMPL_HPP
#define VSOMEIP_V3_CFG_CONFIGURATION_IMPL_HPP

#include <atomic>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <unordered_set>
#include <vector>

#include <boost/property_tree/ptree.hpp>

#include "application_configuration.hpp"
#include "configuration.hpp"
#include "configuration_element.hpp"
#include "e2e.hpp"
#include "routing.hpp"
#include "watchdog.hpp"
#include "service_instance_range.hpp"
#include "trace.hpp"
#include "../../e2e_protection/include/e2exf/config.hpp"
#include "../../security/include/policy.hpp"

namespace vsomeip_v3 {

namespace cfg {

struct client;
struct service;
struct servicegroup;
struct event;
struct eventgroup;
struct watchdog;

struct suppress_t {
    service_t service;
    instance_t instance;
    event_t event;

    inline bool operator<(const suppress_t& entry_) const {
        if(service != entry_.service) {
            return service < entry_.service;
        }
        if(instance != entry_.instance) {
            return instance < entry_.instance;
        }
        if(event != entry_.event) {
            return event < entry_.event;
        }
        return false;
    }
};

class configuration_impl:
        public configuration,
        public std::enable_shared_from_this<configuration_impl> {
public:
    VSOMEIP_EXPORT configuration_impl(const std::string &_path);
    VSOMEIP_EXPORT configuration_impl(const configuration_impl &_other);
    VSOMEIP_EXPORT virtual ~configuration_impl();

    VSOMEIP_EXPORT bool load(const std::string &_name);
#ifndef VSOMEIP_DISABLE_SECURITY
    VSOMEIP_EXPORT bool lazy_load_security(const std::string &_client_host);
#endif // !VSOMEIP_DISABLE_SECURITY
    VSOMEIP_EXPORT bool remote_offer_info_add(service_t _service,
                                              instance_t _instance,
                                              std::uint16_t _port,
                                              bool _reliable,
                                              bool _magic_cookies_enabled);
    VSOMEIP_EXPORT bool remote_offer_info_remove(service_t _service,
                                                 instance_t _instance,
                                                 std::uint16_t _port,
                                                 bool _reliable,
                                                 bool _magic_cookies_enabled,
                                                 bool* _still_offered_remote);

    VSOMEIP_EXPORT const std::string &get_network() const;

    VSOMEIP_EXPORT void set_configuration_path(const std::string &_path);

    VSOMEIP_EXPORT const boost::asio::ip::address & get_unicast_address() const;
    VSOMEIP_EXPORT const boost::asio::ip::address& get_netmask() const;
    VSOMEIP_EXPORT unsigned short get_prefix() const;
    VSOMEIP_EXPORT const std::string &get_device() const;
    VSOMEIP_EXPORT unsigned short get_diagnosis_address() const;
    VSOMEIP_EXPORT std::uint16_t get_diagnosis_mask() const;
    VSOMEIP_EXPORT bool is_v4() const;
    VSOMEIP_EXPORT bool is_v6() const;

    VSOMEIP_EXPORT bool has_console_log() const;
    VSOMEIP_EXPORT bool has_file_log() const;
    VSOMEIP_EXPORT bool has_dlt_log() const;
    VSOMEIP_EXPORT const std::string & get_logfile() const;
    VSOMEIP_EXPORT vsomeip_v3::logger::level_e get_loglevel() const;

    VSOMEIP_EXPORT std::string get_unicast_address(service_t _service, instance_t _instance) const;

    VSOMEIP_EXPORT uint16_t get_reliable_port(service_t _service, instance_t _instance) const;
    VSOMEIP_EXPORT bool has_enabled_magic_cookies(const std::string &_address, uint16_t _port) const;
    VSOMEIP_EXPORT uint16_t get_unreliable_port(service_t _service,
            instance_t _instance) const;

    VSOMEIP_EXPORT void get_configured_timing_requests(
            service_t _service, const std::string &_ip_target,
            std::uint16_t _port_target, method_t _method,
            std::chrono::nanoseconds *_debounce_time,
            std::chrono::nanoseconds *_max_retention_time) const;
    VSOMEIP_EXPORT void get_configured_timing_responses(
            service_t _service, const std::string &_ip_service,
            std::uint16_t _port_service, method_t _method,
            std::chrono::nanoseconds *_debounce_time,
            std::chrono::nanoseconds *_max_retention_time) const;

    VSOMEIP_EXPORT bool is_someip(service_t _service, instance_t _instance) const;

    VSOMEIP_EXPORT bool get_client_port(service_t _service, instance_t _instance,
            uint16_t _remote_port, bool _reliable,
            std::map<bool, std::set<uint16_t> > &_used_client_ports, uint16_t &_client_port) const;

    VSOMEIP_EXPORT bool is_routing_enabled() const;
    VSOMEIP_EXPORT bool is_local_routing() const;

    VSOMEIP_EXPORT const std::string &get_routing_host_name() const;
    VSOMEIP_EXPORT const boost::asio::ip::address &get_routing_host_address() const;
    VSOMEIP_EXPORT port_t get_routing_host_port() const;

    VSOMEIP_EXPORT const boost::asio::ip::address &get_routing_guest_address() const;
    VSOMEIP_EXPORT std::set<std::pair<port_t, port_t> > get_routing_guest_ports(
            uid_t _uid, gid_t _gid) const;

    VSOMEIP_EXPORT client_t get_id(const std::string &_name) const;
    VSOMEIP_EXPORT bool is_configured_client_id(client_t _id) const;

    VSOMEIP_EXPORT std::size_t get_max_dispatchers(const std::string &_name) const;
    VSOMEIP_EXPORT std::size_t get_max_dispatch_time(const std::string &_name) const;
    VSOMEIP_EXPORT std::size_t get_max_detached_thread_wait_time(const std::string& _name) const;
    VSOMEIP_EXPORT std::size_t get_io_thread_count(const std::string &_name) const;
    VSOMEIP_EXPORT int get_io_thread_nice_level(const std::string &_name) const;
    VSOMEIP_EXPORT std::size_t get_request_debouncing(const std::string &_name) const;
    VSOMEIP_EXPORT bool has_session_handling(const std::string &_name) const;

    VSOMEIP_EXPORT std::set<std::pair<service_t, instance_t> > get_remote_services() const;

    VSOMEIP_EXPORT bool get_multicast(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, std::string &_address, uint16_t &_port) const;

    VSOMEIP_EXPORT uint8_t get_threshold(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup) const;

    VSOMEIP_EXPORT void get_event_update_properties(
            service_t _service, instance_t _instance, event_t _event,
            std::chrono::milliseconds &_cycle,
            bool &_change_resets_cycle, bool &_update_on_change_) const;

    VSOMEIP_EXPORT std::uint32_t get_max_message_size_local() const;
    VSOMEIP_EXPORT std::uint32_t get_max_message_size_reliable(const std::string& _address,
                                           std::uint16_t _port) const;
    VSOMEIP_EXPORT std::uint32_t get_max_message_size_unreliable() const;
    VSOMEIP_EXPORT std::uint32_t get_buffer_shrink_threshold() const;

    VSOMEIP_EXPORT bool supports_selective_broadcasts(const boost::asio::ip::address &_address) const;

    VSOMEIP_EXPORT bool is_offered_remote(service_t _service, instance_t _instance) const;

    VSOMEIP_EXPORT bool log_version() const;
    VSOMEIP_EXPORT uint32_t get_log_version_interval() const;

    VSOMEIP_EXPORT bool is_local_service(service_t _service, instance_t _instance) const;

    VSOMEIP_EXPORT reliability_type_e get_event_reliability(
            service_t _service, instance_t _instance, event_t _event) const;

    VSOMEIP_EXPORT reliability_type_e get_service_reliability(
            service_t _service, instance_t _instance) const;

    // Service Discovery configuration
    VSOMEIP_EXPORT bool is_sd_enabled() const;

    VSOMEIP_EXPORT const std::string & get_sd_multicast() const;
    VSOMEIP_EXPORT uint16_t get_sd_port() const;
    VSOMEIP_EXPORT const std::string & get_sd_protocol() const;

    VSOMEIP_EXPORT uint32_t get_sd_initial_delay_min() const;
    VSOMEIP_EXPORT uint32_t get_sd_initial_delay_max() const;
    VSOMEIP_EXPORT int32_t get_sd_repetitions_base_delay() const;
    VSOMEIP_EXPORT uint8_t get_sd_repetitions_max() const;
    VSOMEIP_EXPORT ttl_t get_sd_ttl() const;
    VSOMEIP_EXPORT int32_t get_sd_cyclic_offer_delay() const;
    VSOMEIP_EXPORT int32_t get_sd_request_response_delay() const;
    VSOMEIP_EXPORT std::uint32_t get_sd_offer_debounce_time() const;
    VSOMEIP_EXPORT std::uint32_t get_sd_find_debounce_time() const;

    // Trace configuration
    VSOMEIP_EXPORT std::shared_ptr<cfg::trace> get_trace() const;

    VSOMEIP_EXPORT bool is_watchdog_enabled() const;
    VSOMEIP_EXPORT uint32_t get_watchdog_timeout() const;
    VSOMEIP_EXPORT uint32_t get_allowed_missing_pongs() const;

    VSOMEIP_EXPORT std::uint32_t get_permissions_uds() const;

    VSOMEIP_EXPORT bool check_routing_credentials(client_t _client,
            const vsomeip_sec_client_t *_sec_client) const;

    VSOMEIP_EXPORT bool check_suppress_events(service_t _service,
            instance_t _instance, event_t _event) const;

    VSOMEIP_EXPORT std::map<plugin_type_e, std::set<std::string>> get_plugins(
            const std::string &_name) const;
    // E2E
    VSOMEIP_EXPORT std::map<e2exf::data_identifier_t, std::shared_ptr<cfg::e2e>> get_e2e_configuration() const;
    VSOMEIP_EXPORT bool is_e2e_enabled() const;

    VSOMEIP_EXPORT bool log_memory() const;
    VSOMEIP_EXPORT uint32_t get_log_memory_interval() const;

    VSOMEIP_EXPORT bool log_status() const;
    VSOMEIP_EXPORT uint32_t get_log_status_interval() const;

    VSOMEIP_EXPORT ttl_map_t get_ttl_factor_offers() const;
    VSOMEIP_EXPORT ttl_map_t get_ttl_factor_subscribes() const;

    VSOMEIP_EXPORT std::shared_ptr<debounce_filter_impl_t> get_debounce(
            const std::string &_name,
            service_t _service, instance_t _instance, event_t _event) const;

    VSOMEIP_EXPORT endpoint_queue_limit_t get_endpoint_queue_limit(
            const std::string& _address, std::uint16_t _port) const;
    VSOMEIP_EXPORT endpoint_queue_limit_t get_endpoint_queue_limit_local() const;

    VSOMEIP_EXPORT std::uint32_t get_max_tcp_restart_aborts() const;
    VSOMEIP_EXPORT std::uint32_t get_max_tcp_connect_time() const;

    VSOMEIP_EXPORT bool is_protected_device(
            const boost::asio::ip::address& _address) const;
    VSOMEIP_EXPORT bool is_protected_port(
            const boost::asio::ip::address& _address,
            std::uint16_t _port, bool _reliable) const;
    VSOMEIP_EXPORT bool is_secure_port(
            const boost::asio::ip::address& _address,
            std::uint16_t _port, bool _reliable) const;

    VSOMEIP_EXPORT void set_sd_acceptance_rule(
            const boost::asio::ip::address& _address,
            port_range_t _port_range, port_type_e _type,
            const std::string& _path, bool _reliable, bool _enable, bool _default);
    VSOMEIP_EXPORT void set_sd_acceptance_rules(
                const sd_acceptance_rules_t& _rules, bool _enable);
    VSOMEIP_EXPORT sd_acceptance_rules_t get_sd_acceptance_rules();
    VSOMEIP_EXPORT void set_sd_acceptance_rules_active(
            const boost::asio::ip::address& _address, bool _enable);

    VSOMEIP_EXPORT bool is_secure_service(service_t _service, instance_t _instance) const;

    VSOMEIP_EXPORT int get_udp_receive_buffer_size() const;

    VSOMEIP_EXPORT bool is_tp_client(
            service_t _service,
            instance_t _instance,
            method_t _method) const;
    VSOMEIP_EXPORT bool is_tp_service(
            service_t _service, instance_t _instance, method_t _method) const;
    VSOMEIP_EXPORT void get_tp_configuration(
            service_t _service, instance_t _instance, method_t _method, bool _is_client,
            std::uint16_t &_max_segment_length, std::uint32_t &_separation_time) const;

    VSOMEIP_EXPORT std::uint32_t get_shutdown_timeout() const;

    VSOMEIP_EXPORT bool log_statistics() const;
    VSOMEIP_EXPORT uint32_t get_statistics_interval() const;
    VSOMEIP_EXPORT uint32_t get_statistics_min_freq() const;
    VSOMEIP_EXPORT uint32_t get_statistics_max_messages() const;

    VSOMEIP_EXPORT uint8_t get_max_remote_subscribers() const;

    VSOMEIP_EXPORT partition_id_t get_partition_id(
            service_t _service, instance_t _instance) const;

    VSOMEIP_EXPORT std::map<std::string, std::string> get_additional_data(
            const std::string &_application_name,
            const std::string &_plugin_name);

    VSOMEIP_EXPORT reliability_type_e get_reliability_type(
            const boost::asio::ip::address &_reliable_address,
            const uint16_t &_reliable_port,
            const boost::asio::ip::address &_unreliable_address,
            const uint16_t &_unreliable_port) const;

    VSOMEIP_EXPORT bool is_security_enabled() const;
    VSOMEIP_EXPORT bool is_security_external() const;
    VSOMEIP_EXPORT bool is_security_audit() const;
    VSOMEIP_EXPORT bool is_remote_access_allowed() const;

    VSOMEIP_EXPORT std::shared_ptr<policy_manager_impl> get_policy_manager() const;
    VSOMEIP_EXPORT std::shared_ptr<security> get_security() const;
private:
    void read_data(const std::set<std::string> &_input,
            std::vector<configuration_element> &_elements,
            std::set<std::string> &_failed,
            bool _mandatory_only, bool _read_second_level = false);
#ifndef VSOMEIP_DISABLE_POLICY
    void load_policy_data(const std::string &_input,
            std::vector<configuration_element> &_elements,
            std::set<std::string> &_failed,
            bool _mandatory_only);
#endif // !VSOMEIP_DISABLE_POLICY
    bool load_data(const std::vector<configuration_element> &_elements,
            bool _load_mandatory, bool _load_optional);

    bool load_logging(const configuration_element &_element,
                std::set<std::string> &_warnings);

    bool load_applications(const configuration_element &_element);
    void load_application_data(const boost::property_tree::ptree &_tree,
            const std::string &_file_name);

    std::map<plugin_type_e, std::set<std::string>> load_plugins(
            const boost::property_tree::ptree &_tree,
            const std::string &_application_name);

    struct plugin_config_data_t {
        std::string name_;
        std::string type_;
    };

    void add_plugin(std::map<plugin_type_e, std::set<std::string>> &_plugins,
            const plugin_config_data_t &_plugin_data,
            const std::string& _application_name);

    bool load_routing(const configuration_element &_element);
    bool load_routing_host(const boost::property_tree::ptree &_tree,
            const std::string &_name);
    bool load_routing_guests(const boost::property_tree::ptree &_tree);
    void load_routing_guest_ports(const boost::property_tree::ptree &_tree);
    std::set<std::pair<port_t, port_t> > load_routing_guest_port_range(
            const boost::property_tree::ptree &_tree) const;

    bool load_routing_credentials(const configuration_element &_element); // compatibility
    void load_routing_client_ports(const configuration_element &_element); // compatibility

    void load_tracing(const configuration_element &_element);
    void load_trace_channels(const boost::property_tree::ptree &_tree);
    void load_trace_channel(const boost::property_tree::ptree &_tree);
    void load_trace_filters(const boost::property_tree::ptree &_tree);
    void load_trace_filter(const boost::property_tree::ptree &_tree);
    void load_trace_filter_expressions(
            const boost::property_tree::ptree &_tree,
            std::string &_criteria,
            std::shared_ptr<trace_filter> &_filter);
    void load_trace_filter_match(
            const boost::property_tree::ptree &_data,
            std::tuple<service_t, instance_t, method_t> &_match);

    void load_suppress_events(const configuration_element &_element);
    void load_suppress_events_data(
            const boost::property_tree::ptree &_tree);
    std::set<event_t> load_suppress_multiple_events(
            const boost::property_tree::ptree &_tree);
    uint16_t load_suppress_data(const std::string &_value) const;
    std::set<event_t> load_range_events(event_t _first_event,
            event_t _last_event) const ;
    void insert_suppress_events(service_t  _service,
    instance_t _instance, event_t _event);
    void print_suppress_events(void) const;

    void load_network(const configuration_element &_element);
    void load_device(const configuration_element &_element);

    void load_unicast_address(const configuration_element &_element);
    void load_netmask(const configuration_element &_element);
    void load_diagnosis_address(const configuration_element &_element);
    void load_shutdown_timeout(const configuration_element &_element);

    void load_service_discovery(const configuration_element &_element);
    void load_delays(const boost::property_tree::ptree &_tree);

    void load_npdu_default_timings(const configuration_element &_element);
    void load_services(const configuration_element &_element);
    void load_servicegroup(const boost::property_tree::ptree &_tree);
    void load_service(const boost::property_tree::ptree &_tree,
            const std::string &_unicast_address);
    void load_event(std::shared_ptr<service> &_service,
            const boost::property_tree::ptree &_tree);
    void load_eventgroup(std::shared_ptr<service> &_service,
            const boost::property_tree::ptree &_tree);

    void load_internal_services(const configuration_element &_element);

    void load_clients(const configuration_element &_element);
    void load_client(const boost::property_tree::ptree &_tree);

    std::set<uint16_t> load_client_ports(const boost::property_tree::ptree &_tree);
    std::pair<uint16_t, uint16_t> load_client_port_range(const boost::property_tree::ptree &_tree);

    void load_watchdog(const configuration_element &_element);

    void load_payload_sizes(const configuration_element &_element);
    void load_permissions(const configuration_element &_element);

    void load_security(const configuration_element &_element);

    void load_selective_broadcasts_support(const configuration_element &_element);

    void load_debounce(const configuration_element &_element);
    void load_service_debounce(const boost::property_tree::ptree &_tree,
            debounce_configuration_t &_debounces);
    void load_events_debounce(const boost::property_tree::ptree &_tree,
            std::map<event_t, std::shared_ptr<debounce_filter_impl_t> > &_debounces);
    void load_event_debounce(const boost::property_tree::ptree &_tree,
                std::map<event_t, std::shared_ptr<debounce_filter_impl_t> > &_debounces);
    void load_event_debounce_ignore(const boost::property_tree::ptree &_tree,
            std::map<std::size_t, byte_t> &_ignore);
    void load_acceptances(const configuration_element &_element);
    void load_acceptance_data(const boost::property_tree::ptree &_tree);
    void load_udp_receive_buffer_size(const configuration_element &_element);
    bool load_npdu_debounce_times_configuration(
            const std::shared_ptr<service>& _service,
            const boost::property_tree::ptree &_tree);
    bool load_npdu_debounce_times_for_service(
            const std::shared_ptr<service>& _service, bool _is_request,
            const boost::property_tree::ptree &_tree);
    void load_someip_tp(const std::shared_ptr<service>& _service,
                        const boost::property_tree::ptree &_tree);
    void load_someip_tp_for_service(
            const std::shared_ptr<service>& _service,
            const boost::property_tree::ptree &_tree, bool _is_request);

    servicegroup *find_servicegroup(const std::string &_name) const;
    std::shared_ptr<client> find_client(service_t _service,
            instance_t _instance) const;
    std::shared_ptr<service> find_service(service_t _service, instance_t _instance) const;
    std::shared_ptr<service> find_service_unlocked(service_t _service, instance_t _instance) const;
    std::shared_ptr<service> find_service(service_t _service,
            const std::string &_address, std::uint16_t _port) const;
    std::shared_ptr<eventgroup> find_eventgroup(service_t _service,
            instance_t _instance, eventgroup_t _eventgroup) const;
    bool find_port(uint16_t &_port, uint16_t _remote, bool _reliable,
            std::map<bool, std::set<uint16_t> > &_used_client_ports) const;
    bool find_specific_port(uint16_t &_port, service_t _service,
            instance_t _instance, bool _reliable,
            std::map<bool, std::set<uint16_t> > &_used_client_ports) const;

    void set_magic_cookies_unicast_address();

    bool is_mandatory(const std::string &_name) const;
    bool is_remote(const std::shared_ptr<service>& _service) const;
    bool is_internal_service(service_t _service, instance_t _instance) const;
    bool is_in_port_range(uint16_t _port, std::pair<uint16_t, uint16_t> _port_range) const;

    void set_mandatory(const std::string &_input);
    void trim(std::string &_s);

    void load_e2e(const configuration_element &_element);
    void load_e2e_protected(const boost::property_tree::ptree &_tree);

    void load_ttl_factors(const boost::property_tree::ptree &_tree,
                          ttl_map_t* _target);

    void load_endpoint_queue_sizes(const configuration_element &_element);

    void load_tcp_restart_settings(const configuration_element &_element);

    void load_secure_services(const configuration_element &_element);
    void load_secure_service(const boost::property_tree::ptree &_tree);

    void load_partitions(const configuration_element &_element);
    void load_partition(const boost::property_tree::ptree &_tree);

private:
    std::mutex mutex_;

    const std::string default_unicast_;
    bool is_loaded_;
    bool is_logging_loaded_;

    std::set<std::string> mandatory_;

    std::shared_ptr<policy_manager_impl> policy_manager_;
    std::shared_ptr<security> security_;

protected:
    // Configuration data
    boost::asio::ip::address unicast_;
    boost::asio::ip::address netmask_;
    unsigned short prefix_;
    std::string device_;
    diagnosis_t diagnosis_;
    diagnosis_t diagnosis_mask_;

    std::atomic_bool has_console_log_;
    std::atomic_bool has_file_log_;
    std::atomic_bool has_dlt_log_;
    std::string logfile_;
    mutable std::mutex mutex_loglevel_;
    vsomeip_v3::logger::level_e loglevel_;

    std::map<
        std::string,
        application_configuration
    > applications_;
    std::set<client_t> client_identifiers_;

    mutable std::mutex services_mutex_;
    std::map<service_t,
        std::map<instance_t,
            std::shared_ptr<service> > > services_;

    std::map<std::string, // IP
        std::map<std::uint16_t, // port
            std::map<service_t,
                std::shared_ptr<service>>>> services_by_ip_port_;

    std::set<suppress_t> suppress_events_;
    bool is_suppress_events_enabled_;

    std::list< std::shared_ptr<client> > clients_;

    routing_t routing_;

    bool is_sd_enabled_;
    std::string sd_protocol_;
    std::string sd_multicast_;
    uint16_t sd_port_;

    uint32_t sd_initial_delay_min_;
    uint32_t sd_initial_delay_max_;
    int32_t sd_repetitions_base_delay_;
    uint8_t sd_repetitions_max_;
    ttl_t sd_ttl_;
    int32_t sd_cyclic_offer_delay_;
    int32_t sd_request_response_delay_;
    std::uint32_t sd_offer_debounce_time_;
    std::uint32_t sd_find_debounce_time_;

    std::map<std::string, std::set<uint16_t> > magic_cookies_;

    std::map<std::string, std::map<std::uint16_t, std::uint32_t>> message_sizes_;
    std::uint32_t max_configured_message_size_;
    std::uint32_t max_local_message_size_;
    std::uint32_t max_reliable_message_size_;
    std::uint32_t max_unreliable_message_size_;
    std::uint32_t buffer_shrink_threshold_;

    std::shared_ptr<trace> trace_;

    std::unordered_set<std::string> supported_selective_addresses;

    std::shared_ptr<watchdog> watchdog_;

    std::vector<service_instance_range> internal_service_ranges_;

    bool log_version_;
    uint32_t log_version_interval_;

    enum element_type_e {
        ET_NETWORK,
        ET_UNICAST,
        ET_DEVICE,
        ET_DIAGNOSIS,
        ET_DIAGNOSIS_MASK,
        ET_LOGGING_CONSOLE,
        ET_LOGGING_FILE,
        ET_LOGGING_DLT,
        ET_LOGGING_LEVEL,
        ET_ROUTING,
        ET_SERVICE_DISCOVERY_ENABLE,
        ET_SERVICE_DISCOVERY_PROTOCOL,
        ET_SERVICE_DISCOVERY_MULTICAST,
        ET_SERVICE_DISCOVERY_PORT,
        ET_SERVICE_DISCOVERY_INITIAL_DELAY_MIN,
        ET_SERVICE_DISCOVERY_INITIAL_DELAY_MAX,
        ET_SERVICE_DISCOVERY_REPETITION_BASE_DELAY,
        ET_SERVICE_DISCOVERY_REPETITION_MAX,
        ET_SERVICE_DISCOVERY_TTL,
        ET_SERVICE_DISCOVERY_CYCLIC_OFFER_DELAY,
        ET_SERVICE_DISCOVERY_REQUEST_RESPONSE_DELAY,
        ET_WATCHDOG_ENABLE,
        ET_WATCHDOG_TIMEOUT,
        ET_WATCHDOG_ALLOWED_MISSING_PONGS,
        ET_TRACING_ENABLE,
        ET_TRACING_SD_ENABLE,
        ET_SERVICE_DISCOVERY_OFFER_DEBOUNCE_TIME,
        ET_SERVICE_DISCOVERY_FIND_DEBOUNCE_TIME,
        ET_SERVICE_DISCOVERY_TTL_FACTOR_OFFERS,
        ET_SERVICE_DISCOVERY_TTL_FACTOR_SUBSCRIPTIONS,
        ET_ENDPOINT_QUEUE_LIMITS,
        ET_ENDPOINT_QUEUE_LIMIT_EXTERNAL,
        ET_ENDPOINT_QUEUE_LIMIT_LOCAL,
        ET_TCP_RESTART_ABORTS_MAX,
        ET_TCP_CONNECT_TIME_MAX,
        ET_SD_ACCEPTANCE_REQUIRED,
        ET_NETMASK,
        ET_UDP_RECEIVE_BUFFER_SIZE,
        ET_NPDU_DEFAULT_TIMINGS,
        ET_PLUGIN_NAME,
        ET_PLUGIN_TYPE,
        ET_SHUTDOWN_TIMEOUT,
        ET_MAX_REMOTE_SUBSCRIBERS,
        ET_PARTITIONS,
        ET_SECURITY_AUDIT_MODE,
        ET_SECURITY_REMOTE_ACCESS,
        ET_MAX = 46
    };

    bool is_configured_[ET_MAX];
    std::uint32_t permissions_uds_;

    std::string network_;
    std::string configuration_path_;

    bool e2e_enabled_;
    std::map<e2exf::data_identifier_t, std::shared_ptr<cfg::e2e>> e2e_configuration_;

    bool log_memory_;
    uint32_t log_memory_interval_;

    bool log_status_;
    uint32_t log_status_interval_;

    ttl_map_t ttl_factors_offers_;
    ttl_map_t ttl_factors_subscriptions_;

    debounce_configuration_t debounces_;

    std::map<std::string, std::map<std::uint16_t, endpoint_queue_limit_t>> endpoint_queue_limits_;
    endpoint_queue_limit_t endpoint_queue_limit_external_;
    endpoint_queue_limit_t endpoint_queue_limit_local_;

    uint32_t tcp_restart_aborts_max_;
    uint32_t tcp_connect_time_max_;

    mutable std::mutex sd_acceptance_required_ips_mutex_;
    sd_acceptance_rules_t sd_acceptance_rules_;
    std::set<boost::asio::ip::address> sd_acceptance_rules_active_;

    bool has_issued_methods_warning_;
    bool has_issued_clients_warning_;

    int udp_receive_buffer_size_;

    std::chrono::nanoseconds npdu_default_debounce_requ_;
    std::chrono::nanoseconds npdu_default_debounce_resp_;
    std::chrono::nanoseconds npdu_default_max_retention_requ_;
    std::chrono::nanoseconds npdu_default_max_retention_resp_;

    std::uint32_t shutdown_timeout_;

    mutable std::mutex secure_services_mutex_;
    std::map<service_t, std::set<instance_t> > secure_services_;

    bool log_statistics_;
    uint32_t statistics_interval_;
    uint32_t statistics_min_freq_;
    uint32_t statistics_max_messages_;

    uint8_t max_remote_subscribers_;

    mutable std::mutex partitions_mutex_;
    std::map<service_t,
        std::map<instance_t,
            partition_id_t
        >
    > partitions_;

    std::string path_;

    std::map<std::string,
        std::map<std::string,
            std::map<std::string,
            std::string
            >
        >
    > plugins_additional_;

    std::atomic_bool is_security_enabled_;
    std::atomic_bool is_security_external_;
    std::atomic_bool is_security_audit_;
    std::atomic_bool is_remote_access_allowed_;
};

} // namespace cfg
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_CFG_CONFIGURATION_IMPL_HPP
