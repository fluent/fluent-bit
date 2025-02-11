// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_CONFIGURATION_HPP
#define VSOMEIP_V3_CONFIGURATION_HPP

#include <map>
#include <memory>
#include <set>
#include <string>
#include <chrono>

#include <boost/asio/ip/address.hpp>
#include <boost/icl/interval_set.hpp>

#include <vsomeip/export.hpp>
#include <vsomeip/defines.hpp>
#include <vsomeip/plugin.hpp>
#include <vsomeip/primitive_types.hpp>
#include <vsomeip/vsomeip_sec.h>

#include "trace.hpp"

#include "../../e2e_protection/include/e2exf/config.hpp"
#include "e2e.hpp"


#ifdef ANDROID
#include "internal_android.hpp"
#else
#include "internal.hpp"
#endif // ANDROID

#include "../../security/include/policy.hpp"

#define VSOMEIP_CONFIG_PLUGIN_VERSION              1

namespace vsomeip_v3 {

class policy_manager_impl;
class security;
class event;
struct debounce_filter_impl_t;

class configuration {
public:
    virtual ~configuration()
#ifndef ANDROID
    {}
#else
    ;
#endif

    virtual bool load(const std::string &_name) = 0;
#ifndef VSOMEIP_DISABLE_SECURITY
    virtual bool lazy_load_security(const std::string &_client_host) = 0;
#endif // !VSOMEIP_DISABLE_SECURITY
    virtual bool remote_offer_info_add(service_t _service,
                                       instance_t _instance,
                                       std::uint16_t _port,
                                       bool _reliable,
                                       bool _magic_cookies_enabled) = 0;
    virtual bool remote_offer_info_remove(service_t _service,
                                          instance_t _instance,
                                          std::uint16_t _port,
                                          bool _reliable,
                                          bool _magic_cookies_enabled,
                                          bool* _still_offered_remote) = 0;

    virtual const std::string &get_network() const = 0;

    virtual const boost::asio::ip::address & get_unicast_address() const = 0;
    virtual const boost::asio::ip::address& get_netmask() const = 0;
    virtual unsigned short get_prefix() const = 0;
    virtual const std::string &get_device() const = 0;
    virtual diagnosis_t get_diagnosis_address() const = 0;
    virtual diagnosis_t get_diagnosis_mask() const = 0;
    virtual bool is_v4() const = 0;
    virtual bool is_v6() const = 0;

    virtual bool has_console_log() const = 0;
    virtual bool has_file_log() const = 0;
    virtual bool has_dlt_log() const = 0;
    virtual const std::string &get_logfile() const = 0;
    virtual logger::level_e get_loglevel() const = 0;

    virtual bool is_routing_enabled() const = 0;
    virtual const std::string &get_routing_host_name() const = 0;
    virtual const boost::asio::ip::address &get_routing_host_address() const = 0;
    virtual port_t get_routing_host_port() const = 0;

    virtual const boost::asio::ip::address &get_routing_guest_address() const = 0;
    virtual std::set<std::pair<port_t, port_t> > get_routing_guest_ports(
            uid_t _uid, gid_t _gid) const = 0;

    virtual bool is_local_routing() const = 0;

    virtual std::string get_unicast_address(service_t _service,
            instance_t _instance) const = 0;
    virtual uint16_t get_reliable_port(service_t _service,
            instance_t _instance) const = 0;
    virtual bool has_enabled_magic_cookies(const std::string &_address,
            uint16_t _port) const = 0;
    virtual uint16_t get_unreliable_port(service_t _service,
            instance_t _instance) const = 0;

    virtual void get_configured_timing_requests(
            service_t _service, const std::string &_ip_target,
            std::uint16_t _port_target, method_t _method,
            std::chrono::nanoseconds *_debounce_time,
            std::chrono::nanoseconds *_max_retention_time) const = 0;
    virtual void get_configured_timing_responses(
            service_t _service, const std::string &_ip_service,
            std::uint16_t _port_service, method_t _method,
            std::chrono::nanoseconds *_debounce_time,
            std::chrono::nanoseconds *_max_retention_time) const = 0;

    virtual bool is_someip(service_t _service, instance_t _instance) const = 0;

    virtual bool get_client_port(service_t _service, instance_t _instance,
            uint16_t _remote_port, bool _reliable,
            std::map<bool, std::set<uint16_t> > &_used_client_ports, uint16_t &_client_port) const = 0;

    virtual std::set<std::pair<service_t, instance_t> > get_remote_services() const = 0;

    virtual bool get_multicast(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, std::string &_address, uint16_t &_port) const = 0;

    virtual uint8_t get_threshold(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup) const = 0;

    virtual void get_event_update_properties(
            service_t _service, instance_t _instance, event_t _event,
            std::chrono::milliseconds &_cycle,
            bool &_change_resets_cycle, bool &_update_on_change_) const = 0;

    virtual client_t get_id(const std::string &_name) const = 0;
    virtual bool is_configured_client_id(client_t _id) const = 0;

    virtual std::size_t get_max_dispatchers(const std::string &_name) const = 0;
    virtual std::size_t get_max_dispatch_time(const std::string &_name) const = 0;
    virtual std::size_t get_max_detached_thread_wait_time(const std::string& _name) const = 0;
    virtual std::size_t get_io_thread_count(const std::string &_name) const = 0;
    virtual int get_io_thread_nice_level(const std::string &_name) const = 0;
    virtual std::size_t get_request_debouncing(const std::string &_name) const = 0;
    virtual bool has_session_handling(const std::string &_name) const = 0;

    virtual std::uint32_t get_max_message_size_local() const = 0;
    virtual std::uint32_t get_max_message_size_reliable(const std::string& _address,
                                                    std::uint16_t _port) const = 0;
    virtual std::uint32_t get_max_message_size_unreliable() const = 0;
    virtual std::uint32_t get_buffer_shrink_threshold() const = 0;

    virtual bool supports_selective_broadcasts(const boost::asio::ip::address &_address) const = 0;

    virtual bool is_offered_remote(service_t _service, instance_t _instance) const = 0;

    virtual bool is_local_service(service_t _service, instance_t _instance) const = 0;

    virtual reliability_type_e get_event_reliability(
            service_t _service, instance_t _instance, event_t _event) const = 0;
    virtual reliability_type_e get_service_reliability(
            service_t _service, instance_t _instance) const = 0;

    // Service Discovery configuration
    virtual bool is_sd_enabled() const = 0;

    virtual const std::string & get_sd_multicast() const = 0;
    virtual uint16_t get_sd_port() const = 0;
    virtual const std::string & get_sd_protocol() const = 0;

    virtual uint32_t get_sd_initial_delay_min() const = 0;
    virtual uint32_t get_sd_initial_delay_max() const = 0;
    virtual int32_t get_sd_repetitions_base_delay() const = 0;
    virtual uint8_t get_sd_repetitions_max() const = 0;
    virtual ttl_t get_sd_ttl() const = 0;
    virtual int32_t get_sd_cyclic_offer_delay() const = 0;
    virtual int32_t get_sd_request_response_delay() const = 0;
    virtual std::uint32_t get_sd_offer_debounce_time() const = 0;
    virtual std::uint32_t get_sd_find_debounce_time() const = 0;

    // Trace configuration
    virtual std::shared_ptr<cfg::trace> get_trace() const = 0;

    // Watchdog
    virtual bool is_watchdog_enabled() const = 0;
    virtual uint32_t get_watchdog_timeout() const = 0;
    virtual uint32_t get_allowed_missing_pongs() const = 0;

    // File permissions
    virtual std::uint32_t get_permissions_uds() const = 0;

    virtual bool log_version() const = 0;
    virtual uint32_t get_log_version_interval() const = 0;

    // Plugins
    virtual std::map<plugin_type_e, std::set<std::string>> get_plugins(
            const std::string &_name) const = 0;

    virtual void set_configuration_path(const std::string &_path) = 0;

    virtual std::map<std::string, std::string> get_additional_data(
            const std::string &_application_name,
            const std::string &_plugin_name) = 0;

    //E2E
    virtual std::map<e2exf::data_identifier_t, std::shared_ptr<cfg::e2e>> get_e2e_configuration() const = 0;
    virtual bool is_e2e_enabled() const = 0;

    virtual bool log_memory() const = 0;
    virtual uint32_t get_log_memory_interval() const = 0;

    virtual bool log_status() const = 0;
    virtual uint32_t get_log_status_interval() const = 0;

    // TTL factor
    typedef std::uint32_t ttl_factor_t;
    typedef std::map<service_t, std::map<instance_t, ttl_factor_t>> ttl_map_t;
    virtual ttl_map_t get_ttl_factor_offers() const = 0;
    virtual ttl_map_t get_ttl_factor_subscribes() const = 0;

    // Debouncing
    virtual std::shared_ptr<debounce_filter_impl_t> get_debounce(
            const std::string &_name,
            service_t _service, instance_t _instance, event_t _event) const = 0;

    // Queue size limit endpoints
    typedef std::uint32_t endpoint_queue_limit_t;
    virtual endpoint_queue_limit_t get_endpoint_queue_limit(
            const std::string& _address, std::uint16_t _port) const = 0;
    virtual endpoint_queue_limit_t get_endpoint_queue_limit_local() const = 0;

    virtual std::uint32_t get_max_tcp_restart_aborts() const = 0;
    virtual std::uint32_t get_max_tcp_connect_time() const = 0;

    // Acceptance handling
    virtual bool is_protected_device(
            const boost::asio::ip::address& _address) const = 0;
    virtual bool is_protected_port(
            const boost::asio::ip::address& _address, std::uint16_t _port,
            bool _reliable) const = 0;
    virtual bool is_secure_port(
                const boost::asio::ip::address& _address, std::uint16_t _port,
                bool _reliable) const = 0;

    typedef std::pair<std::uint16_t, std::uint16_t> port_range_t;
    virtual void set_sd_acceptance_rule(
            const boost::asio::ip::address &_address,
            port_range_t _port_range, port_type_e _type,
            const std::string &_path, bool _reliable, bool _enable, bool _default) = 0;

    typedef std::map<
        boost::asio::ip::address, // other device
        std::pair<
            std::string, // path to file that determines whether or not IPsec is active
            std::map<
                bool, // false = unreliable (aka UDP), true = reliable (aka TCP)
                std::pair<
                    boost::icl::interval_set<std::uint16_t>, // optional (aka semi-secure) port range
                    boost::icl::interval_set<std::uint16_t>  // secure port range
                >
            >
        >
    > sd_acceptance_rules_t;
    virtual sd_acceptance_rules_t get_sd_acceptance_rules() = 0;
    virtual void set_sd_acceptance_rules_active(
            const boost::asio::ip::address& _address, bool _enable) = 0;

    virtual bool is_secure_service(service_t _service, instance_t _instance) const = 0;

    virtual int get_udp_receive_buffer_size() const = 0;

    virtual bool check_routing_credentials(client_t _client,
            const vsomeip_sec_client_t *_sec_client) const = 0;

    virtual bool check_suppress_events(service_t _service,
            instance_t _instance, event_t _event) const = 0;

    // SOME/IP-TP
    virtual bool is_tp_client(
            service_t _service, instance_t _instance,
            method_t _method) const = 0;
    virtual bool is_tp_service(
            service_t _service, instance_t _instance,
            method_t _method) const = 0;
    virtual void get_tp_configuration(
            service_t _service, instance_t _instance, method_t _method, bool _is_client,
            std::uint16_t &_max_segment_length, std::uint32_t &_separation_time) const = 0;

    // routing shutdown timeout
    virtual std::uint32_t get_shutdown_timeout() const = 0;

    virtual bool log_statistics() const = 0;
    virtual uint32_t get_statistics_interval() const = 0;
    virtual uint32_t get_statistics_min_freq() const = 0;
    virtual uint32_t get_statistics_max_messages() const = 0;

    virtual uint8_t get_max_remote_subscribers() const = 0;

    virtual partition_id_t get_partition_id(
            service_t _service, instance_t _instance) const = 0;

    virtual reliability_type_e get_reliability_type(
            const boost::asio::ip::address &_reliable_address,
            const uint16_t &_reliable_port,
            const boost::asio::ip::address &_unreliable_address,
            const uint16_t &_unreliable_port) const = 0;

    // security
    virtual bool is_security_enabled() const = 0;
    virtual bool is_security_external() const = 0;
    virtual bool is_security_audit() const = 0;
    virtual bool is_remote_access_allowed() const = 0;
    virtual std::shared_ptr<policy_manager_impl> get_policy_manager() const = 0;
    virtual std::shared_ptr<security> get_security() const = 0;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_CONFIGURATION_HPP
