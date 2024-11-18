// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <cctype>
#include <fstream>
#include <functional>
#include <limits>
#include <mutex>
#include <set>
#include <sstream>
#include <utility>

#define WIN32_LEAN_AND_MEAN
#define BOOST_BIND_GLOBAL_PLACEHOLDERS

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <vsomeip/constants.hpp>
#include <vsomeip/plugins/application_plugin.hpp>
#include <vsomeip/plugins/pre_configuration_plugin.hpp>
#include <vsomeip/internal/logger.hpp>
#include <vsomeip/structured_types.hpp>
#include <vsomeip/internal/plugin_manager.hpp>

#include "../include/client.hpp"
#include "../include/configuration_impl.hpp"
#include "../include/event.hpp"
#include "../include/eventgroup.hpp"
#include "../include/service.hpp"
#include "../../logger/include/logger_impl.hpp"
#include "../../protocol/include/protocol.hpp"
#include "../../routing/include/event.hpp"
#include "../../service_discovery/include/defines.hpp"
#include "../../utility/include/utility.hpp"
#include "../../security/include/policy_manager_impl.hpp"
#include "../../security/include/security.hpp"

namespace vsomeip_v3 {
namespace cfg {

configuration_impl::configuration_impl(const std::string &_path)
    : default_unicast_("local"),
      is_loaded_(false),
      is_logging_loaded_(false),
      prefix_(VSOMEIP_PREFIX),
      diagnosis_(VSOMEIP_DIAGNOSIS_ADDRESS),
      diagnosis_mask_(0xFF00),
      has_console_log_(true),
      has_file_log_(false),
      has_dlt_log_(false),
      logfile_("/tmp/vsomeip.log"),
      loglevel_(vsomeip_v3::logger::level_e::LL_INFO),
      is_sd_enabled_(VSOMEIP_SD_DEFAULT_ENABLED),
      sd_protocol_(VSOMEIP_SD_DEFAULT_PROTOCOL),
      sd_multicast_(VSOMEIP_SD_DEFAULT_MULTICAST),
      sd_port_(VSOMEIP_SD_DEFAULT_PORT),
      sd_initial_delay_min_(VSOMEIP_SD_DEFAULT_INITIAL_DELAY_MIN),
      sd_initial_delay_max_(VSOMEIP_SD_DEFAULT_INITIAL_DELAY_MAX),
      sd_repetitions_base_delay_(VSOMEIP_SD_DEFAULT_REPETITIONS_BASE_DELAY),
      sd_repetitions_max_(VSOMEIP_SD_DEFAULT_REPETITIONS_MAX),
      sd_ttl_(VSOMEIP_SD_DEFAULT_TTL),
      sd_cyclic_offer_delay_(VSOMEIP_SD_DEFAULT_CYCLIC_OFFER_DELAY),
      sd_request_response_delay_(VSOMEIP_SD_DEFAULT_REQUEST_RESPONSE_DELAY),
      sd_offer_debounce_time_(VSOMEIP_SD_DEFAULT_OFFER_DEBOUNCE_TIME),
      sd_find_debounce_time_(VSOMEIP_SD_DEFAULT_FIND_DEBOUNCE_TIME),
      max_configured_message_size_(0),
      max_local_message_size_(0),
      max_reliable_message_size_(0),
      max_unreliable_message_size_(0),
      buffer_shrink_threshold_(VSOMEIP_DEFAULT_BUFFER_SHRINK_THRESHOLD),
      trace_(std::make_shared<trace>()),
      watchdog_(std::make_shared<watchdog>()),
      log_version_(true),
      log_version_interval_(10),
      permissions_uds_(VSOMEIP_DEFAULT_UDS_PERMISSIONS),
      network_("vsomeip"),
      e2e_enabled_(false),
      log_memory_(false),
      log_memory_interval_(0),
      log_status_(false),
      log_status_interval_(0),
      endpoint_queue_limit_external_(QUEUE_SIZE_UNLIMITED),
      endpoint_queue_limit_local_(QUEUE_SIZE_UNLIMITED),
      tcp_restart_aborts_max_(VSOMEIP_MAX_TCP_RESTART_ABORTS),
      tcp_connect_time_max_(VSOMEIP_MAX_TCP_CONNECT_TIME),
      has_issued_methods_warning_(false),
      has_issued_clients_warning_(false),
      udp_receive_buffer_size_(VSOMEIP_DEFAULT_UDP_RCV_BUFFER_SIZE),
      npdu_default_debounce_requ_(VSOMEIP_DEFAULT_NPDU_DEBOUNCING_NANO),
      npdu_default_debounce_resp_(VSOMEIP_DEFAULT_NPDU_DEBOUNCING_NANO),
      npdu_default_max_retention_requ_(VSOMEIP_DEFAULT_NPDU_MAXIMUM_RETENTION_NANO),
      npdu_default_max_retention_resp_(VSOMEIP_DEFAULT_NPDU_MAXIMUM_RETENTION_NANO),
      shutdown_timeout_(VSOMEIP_DEFAULT_SHUTDOWN_TIMEOUT),
      log_statistics_(true),
      statistics_interval_(VSOMEIP_DEFAULT_STATISTICS_INTERVAL),
      statistics_min_freq_(VSOMEIP_DEFAULT_STATISTICS_MIN_FREQ),
      statistics_max_messages_(VSOMEIP_DEFAULT_STATISTICS_MAX_MSG),
      max_remote_subscribers_(VSOMEIP_DEFAULT_MAX_REMOTE_SUBSCRIBERS),
      path_(_path),
      is_security_enabled_(false),
      is_security_external_(false),
      is_security_audit_(false),
      is_remote_access_allowed_(true) {

    policy_manager_ = std::make_shared<policy_manager_impl>();
    security_ = std::make_shared<security>(policy_manager_);
    unicast_ = unicast_.from_string(VSOMEIP_UNICAST_ADDRESS);
    netmask_ = netmask_.from_string(VSOMEIP_NETMASK);
    for (auto i = 0; i < ET_MAX; i++)
        is_configured_[i] = false;

#ifdef _WIN32
    routing_.host_.unicast_ = boost::asio::ip::make_address("127.0.0.1");
    routing_.host_.port_ = 31490;
    routing_.guests_.unicast_ = routing_.host_.unicast_;
    routing_.guests_.ports_[{ ANY_UID, ANY_GID }].emplace(31492, 31999);
#endif
}

configuration_impl::configuration_impl(const configuration_impl &_other)
    : std::enable_shared_from_this<configuration_impl>(_other),
      default_unicast_(_other.default_unicast_),
      is_loaded_(_other.is_loaded_),
      is_logging_loaded_(_other.is_logging_loaded_),
      mandatory_(_other.mandatory_),
      has_console_log_(_other.has_console_log_.load()),
      has_file_log_(_other.has_file_log_.load()),
      has_dlt_log_(_other.has_dlt_log_.load()),
      max_configured_message_size_(_other.max_configured_message_size_),
      max_local_message_size_(_other.max_local_message_size_),
      max_reliable_message_size_(_other.max_reliable_message_size_),
      max_unreliable_message_size_(_other.max_unreliable_message_size_),
      buffer_shrink_threshold_(_other.buffer_shrink_threshold_),
      permissions_uds_(VSOMEIP_DEFAULT_UDS_PERMISSIONS),
      endpoint_queue_limit_external_(_other.endpoint_queue_limit_external_),
      endpoint_queue_limit_local_(_other.endpoint_queue_limit_local_),
      tcp_restart_aborts_max_(_other.tcp_restart_aborts_max_),
      tcp_connect_time_max_(_other.tcp_connect_time_max_),
      udp_receive_buffer_size_(_other.udp_receive_buffer_size_),
      npdu_default_debounce_requ_(_other.npdu_default_debounce_requ_),
      npdu_default_debounce_resp_(_other.npdu_default_debounce_resp_),
      npdu_default_max_retention_requ_(_other.npdu_default_max_retention_requ_),
      npdu_default_max_retention_resp_(_other.npdu_default_max_retention_resp_),
      shutdown_timeout_(_other.shutdown_timeout_),
      path_(_other.path_) {

    applications_.insert(_other.applications_.begin(), _other.applications_.end());
    client_identifiers_ = _other.client_identifiers_;
    services_.insert(_other.services_.begin(), _other.services_.end());
    clients_ = _other.clients_;

    unicast_ = _other.unicast_;
    netmask_ = _other.netmask_;
    device_ = _other.device_;
    diagnosis_ = _other.diagnosis_;
    diagnosis_mask_ = _other.diagnosis_mask_;

    logfile_ = _other.logfile_;

    loglevel_ = _other.loglevel_;

    routing_ = _other.routing_;

    is_sd_enabled_ = _other.is_sd_enabled_;
    sd_multicast_ = _other.sd_multicast_;
    sd_port_ = _other.sd_port_;
    sd_protocol_ = _other.sd_protocol_;

    sd_initial_delay_min_ = _other.sd_initial_delay_min_;
    sd_initial_delay_max_ = _other.sd_initial_delay_max_;
    sd_repetitions_base_delay_= _other.sd_repetitions_base_delay_;
    sd_repetitions_max_ = _other.sd_repetitions_max_;
    sd_ttl_ = _other.sd_ttl_;
    sd_cyclic_offer_delay_= _other.sd_cyclic_offer_delay_;
    sd_request_response_delay_= _other.sd_request_response_delay_;
    sd_offer_debounce_time_ = _other.sd_offer_debounce_time_;
    sd_find_debounce_time_ = _other.sd_find_debounce_time_;

    trace_ = std::make_shared<trace>(*_other.trace_.get());
    supported_selective_addresses = _other.supported_selective_addresses;
    watchdog_ = std::make_shared<watchdog>(*_other.watchdog_.get());
    internal_service_ranges_ = _other.internal_service_ranges_;
    log_version_ = _other.log_version_;
    log_version_interval_ = _other.log_version_interval_;

    magic_cookies_.insert(_other.magic_cookies_.begin(), _other.magic_cookies_.end());
    message_sizes_ = _other.message_sizes_;

    for (auto i = 0; i < ET_MAX; i++)
        is_configured_[i] = _other.is_configured_[i];

    network_ = _other.network_;
    configuration_path_ = _other.configuration_path_;

    e2e_enabled_ = _other.e2e_enabled_;
    e2e_configuration_ = _other.e2e_configuration_;

    log_memory_ = _other.log_memory_;
    log_memory_interval_ = _other.log_memory_interval_;
    log_status_ = _other.log_status_;
    log_status_interval_ = _other.log_status_interval_;

    ttl_factors_offers_ = _other.ttl_factors_offers_;
    ttl_factors_subscriptions_ = _other.ttl_factors_subscriptions_;

    debounces_ = _other.debounces_;
    endpoint_queue_limits_ = _other.endpoint_queue_limits_;

    sd_acceptance_rules_ = _other.sd_acceptance_rules_;

    has_issued_methods_warning_ = _other.has_issued_methods_warning_;
    has_issued_clients_warning_ = _other.has_issued_clients_warning_;

    log_statistics_ = _other.log_statistics_;
    statistics_interval_ = _other.statistics_interval_;
    statistics_min_freq_ = _other.statistics_min_freq_;
    statistics_max_messages_ = _other.statistics_max_messages_;
    max_remote_subscribers_ = _other.max_remote_subscribers_;

    is_security_enabled_ = _other.is_security_enabled_.load();
    is_security_external_ = _other.is_security_external_.load();
    is_security_audit_ = _other.is_security_audit_.load();
    is_remote_access_allowed_ = _other.is_remote_access_allowed_.load();
}

configuration_impl::~configuration_impl() {
}

bool configuration_impl::load(const std::string &_name) {
    std::lock_guard<std::mutex> its_lock(mutex_);
    if (is_loaded_)
        return true;

    // Environment
    char *its_env;

    // Predefine file / folder
    std::string its_file(VSOMEIP_DEFAULT_CONFIGURATION_FILE); // configuration file
    std::string its_folder(VSOMEIP_DEFAULT_CONFIGURATION_FOLDER); // configuration folder

    if (!path_.empty()) {
        if (utility::is_file(path_)) {
            its_file = path_;
            its_folder = "";
        } else {
            its_file = "";
            its_folder = path_;
        }
    }

    // Override with local file / folder (if existing)
    std::string its_local_file(VSOMEIP_LOCAL_CONFIGURATION_FILE);
    if (utility::is_file(its_local_file)) {
        its_file = its_local_file;
    }

    std::string its_local_folder(VSOMEIP_LOCAL_CONFIGURATION_FOLDER);
    if (utility::is_folder(its_local_folder)) {
        its_folder = its_local_folder;
    }

    // Override with path from environment (if existing)
    std::string its_named_configuration(VSOMEIP_ENV_CONFIGURATION);
    its_named_configuration += "_" + _name;

    its_env = getenv(its_named_configuration.c_str());
    if (nullptr == its_env)
        its_env = getenv(VSOMEIP_ENV_CONFIGURATION);
    if (nullptr != its_env) {
        if (utility::is_file(its_env)) {
            its_file = its_env;
            its_folder = "";
        } else if (utility::is_folder(its_env)) {
            its_folder = its_env;
            its_file = "";
        }
    }

    std::set<std::string> its_input;
    if (its_file != "") {
        its_input.insert(its_file);
    }
    if (its_folder != "") {
        its_input.insert(its_folder);
#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
        // load security configuration files from UID_GID sub folder if existing
        std::stringstream its_security_config_folder;
        its_security_config_folder << its_folder << "/" << getuid() << "_" << getgid();
        if (utility::is_folder(its_security_config_folder.str())) {
            its_input.insert(its_security_config_folder.str());
        }
#endif
    }

    // Determine standard configuration file
    its_env = getenv(VSOMEIP_ENV_MANDATORY_CONFIGURATION_FILES);
    if (nullptr != its_env) {
        std::string its_temp(its_env);
        set_mandatory(its_temp);
    } else {
        set_mandatory(VSOMEIP_MANDATORY_CONFIGURATION_FILES);
    }

    // Start reading
    std::set<std::string> its_failed;

    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    std::vector<configuration_element> its_mandatory_elements;
    std::vector<configuration_element> its_optional_elements;

    // Look for the standard configuration file
    read_data(its_input, its_mandatory_elements, its_failed, true);
    load_data(its_mandatory_elements, true, false);

    // If the configuration is incomplete, this is the routing manager configuration or
    // the routing is yet unknown, read the full set of configuration files
    if (its_mandatory_elements.empty() || _name == get_routing_host_name()
        || "" == get_routing_host_name()) {
        read_data(its_input, its_optional_elements, its_failed, false);
        load_data(its_mandatory_elements, false, true);
        load_data(its_optional_elements, true, true);
    }

    // Dummy initialization; if logger configs were not found use default
    if (!is_logging_loaded_) {
        logger::logger_impl::init(shared_from_this());
    }

    // Tell, if reading of configuration file(s) failed.
    // (This may file if the logger configuration is incomplete/missing).
    for (const auto& f : its_failed)
        VSOMEIP_WARNING << "Reading of configuration file \""
            << f << "\" failed. Configuration may be incomplete.";

    // set global unicast address for all services with magic cookies enabled
    set_magic_cookies_unicast_address();

    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();

    for (const auto& i : its_input) {
        if (utility::is_file(i))
            VSOMEIP_INFO << "Using configuration file: \"" << i << "\".";

        if (utility::is_folder(i))
            VSOMEIP_INFO << "Using configuration folder: \"" << i << "\".";
    }

    VSOMEIP_INFO << "Parsed vsomeip configuration in "
            << std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count()
            << "ms";

    is_loaded_ = true;
    return is_loaded_;
}

#ifndef VSOMEIP_DISABLE_SECURITY
bool configuration_impl::lazy_load_security(const std::string &_client_host) {
    bool result(false);

    std::string its_folder = policy_manager_->get_policy_extension_path(_client_host);
    if (!its_folder.empty()) {
        std::set<std::string> its_input;
        std::set<std::string> its_failed;
        std::vector<configuration_element> its_mandatory_elements;

        its_input.insert(its_folder);
        // load security configuration files from UID_GID sub folder if existing
        std::string its_security_config_folder = policy_manager_->get_security_config_folder(its_folder);

        if (!its_security_config_folder.empty())
            its_input.insert(its_security_config_folder);

        read_data(its_input, its_mandatory_elements, its_failed, true, true);

        for (const auto& e : its_mandatory_elements) {
            policy_manager_->load(e, true);
        }

        for (auto f : its_failed)
            VSOMEIP_WARNING << __func__ << ": Reading of configuration file \""
                << f << "\" failed. Configuration may be incomplete.";

        result = (its_failed.empty() && !its_mandatory_elements.empty());
        if (result)
            policy_manager_->set_is_policy_extension_loaded(_client_host, true);
    }

    return result;
}
#endif // !VSOMEIP_DISABLE_SECURITY

bool
configuration_impl::check_routing_credentials(
        client_t _client, const vsomeip_sec_client_t *_sec_client) const {

    return (_client != get_id(routing_.host_.name_) ||
            VSOMEIP_SEC_OK == security_->authenticate_router(_sec_client));
}

bool configuration_impl::remote_offer_info_add(service_t _service,
                                               instance_t _instance,
                                               std::uint16_t _port,
                                               bool _reliable,
                                               bool _magic_cookies_enabled) {
    bool ret = false;
    if (!is_loaded_) {
        VSOMEIP_ERROR << __func__ << " shall only be called after normal"
                "configuration has been parsed";
    } else {
        auto its_service = std::make_shared<service>();
        its_service->service_ = _service;
        its_service->instance_ = _instance;
        its_service->reliable_ = its_service->unreliable_ = ILLEGAL_PORT;
        _reliable ?
                its_service->reliable_ = _port :
                its_service->unreliable_ = _port;
        its_service->unicast_address_ = default_unicast_;
        its_service->multicast_address_ = "";
        its_service->multicast_port_ = ILLEGAL_PORT;
        its_service->protocol_ = "someip";

        {
            std::lock_guard<std::mutex> its_lock(services_mutex_);
            bool updated(false);
            auto found_service = services_.find(its_service->service_);
            if (found_service != services_.end()) {
                auto found_instance = found_service->second.find(its_service->instance_);
                if (found_instance != found_service->second.end()) {
                    VSOMEIP_INFO << "Updating remote configuration for service ["
                            << std::hex << std::setw(4) << std::setfill('0')
                            << its_service->service_ << "." << its_service->instance_ << "]";
                    if (_reliable) {
                        found_instance->second->reliable_ = its_service->reliable_;
                    } else {
                        found_instance->second->unreliable_ = its_service->unreliable_;
                    }
                    updated = true;
                }
            }
            if (!updated) {
                services_[_service][_instance] = its_service;
                VSOMEIP_INFO << "Added new remote configuration for service ["
                        << std::hex << std::setfill('0')
                        << std::setw(4) << its_service->service_ << "."
                        << std::setw(4) << its_service->instance_ << "]";
            }
            if (_magic_cookies_enabled) {
                magic_cookies_[its_service->unicast_address_].insert(its_service->reliable_);
            }
        }
        ret = true;
    }
    return ret;
}

bool configuration_impl::remote_offer_info_remove(service_t _service,
                                                  instance_t _instance,
                                                  std::uint16_t _port,
                                                  bool _reliable,
                                                  bool _magic_cookies_enabled,
                                                  bool* _still_offered_remote) {
    (void)_port;
    (void)_magic_cookies_enabled;
    bool ret = false;
    if (!is_loaded_) {
        VSOMEIP_ERROR << __func__ << " shall only be called after normal"
                "configuration has been parsed";
    } else {
        std::lock_guard<std::mutex> its_lock(services_mutex_);
        auto found_service = services_.find(_service);
        if (found_service != services_.end()) {
            auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                VSOMEIP_INFO << "Removing remote configuration for service ["
                        << std::hex << std::setw(4) << std::setfill('0')
                        << _service << "." << _instance << "]";
                if (_reliable) {
                    found_instance->second->reliable_ = ILLEGAL_PORT;
                    // TODO delete from magic_cookies_map without overwriting
                    // configurations from other services offered on the same port
                } else {
                    found_instance->second->unreliable_ = ILLEGAL_PORT;
                }
                *_still_offered_remote = (
                        found_instance->second->unreliable_ != ILLEGAL_PORT ||
                        found_instance->second->reliable_ != ILLEGAL_PORT);
                ret = true;
            }
        }
    }
    return ret;
}

void configuration_impl::read_data(const std::set<std::string> &_input,
        std::vector<configuration_element> &_elements, std::set<std::string> &_failed,
        bool _mandatory_only, bool _read_second_level) {
    for (auto i : _input) {
        if (utility::is_file(i)) {
            load_policy_data(i, _elements, _failed, _mandatory_only);
        } else if (utility::is_folder(i)) {
            // Use the map to ensure the configuration files are read in
            // the ascending order of their names. This allows to use
            // specific configuration file names to overwrite generic
            // (or generated) parts of the configuration.
            std::map<std::string, bool> its_names;
            boost::filesystem::path its_path(i);
            for (auto j = boost::filesystem::directory_iterator(its_path);
                    j != boost::filesystem::directory_iterator();
                    j++) {
                if (!boost::filesystem::is_directory(j->path())) {
                    its_names[j->path().string()] = _mandatory_only;
                } else if(_read_second_level) {
                    //_read_second_level to read the second level folders only after
                    // the start, without this the ECU block
                    std::string name = j->path().string() + "/vsomeip_security.json";
                    if (utility::is_file(name))
                        its_names[name] = true;
                }
            }

            for (const auto &n : its_names)
                load_policy_data(n.first, _elements, _failed, n.second);
        }
    }
}

void configuration_impl::load_policy_data(const std::string &_input,
        std::vector<configuration_element> &_elements, std::set<std::string> &_failed,
        bool _mandatory_only) {
        if (is_mandatory(_input) == _mandatory_only) {
#ifndef VSOMEIP_DISABLE_SECURITY
            if (policy_manager_->is_policy_extension(_input)) {
                policy_manager_->set_policy_extension_base_path(_input);
            }
#endif
            boost::property_tree::ptree its_tree;
            try {
                boost::property_tree::json_parser::read_json(_input, its_tree);
                _elements.push_back({ _input, its_tree });
            }
            catch (boost::property_tree::json_parser_error&) {
                _failed.insert(_input);
            }
        }
}

bool configuration_impl::load_data(const std::vector<configuration_element> &_elements,
        bool _load_mandatory, bool _load_optional) {
    // Load logging configuration data
    std::set<std::string> its_warnings;

    if (!is_logging_loaded_) {
        for (const auto& e : _elements)
            is_logging_loaded_
                = load_logging(e, its_warnings) || is_logging_loaded_;

        if (is_logging_loaded_) {
            logger::logger_impl::init(shared_from_this());
            for (const auto& w : its_warnings)
                VSOMEIP_WARNING << w;
        }
    }

    bool has_routing(false);
    bool has_applications(false);
    if (_load_mandatory) {
        // Load mandatory configuration data
        for (const auto& e : _elements) {
            has_routing = load_routing(e) || has_routing;
            has_applications = load_applications(e) || has_applications;
            load_network(e);
            load_diagnosis_address(e);
            load_shutdown_timeout(e);
            load_payload_sizes(e);
            load_endpoint_queue_sizes(e);
            load_tcp_restart_settings(e);
            load_permissions(e);
            load_security(e);
            load_tracing(e);
            load_udp_receive_buffer_size(e);
            load_services(e);
        }
    }

    if (_load_optional) {
        for (const auto& e : _elements) {
            load_unicast_address(e);
            load_netmask(e);
            load_device(e);
            load_service_discovery(e);
            load_npdu_default_timings(e);
            load_internal_services(e);
            load_clients(e);
            load_watchdog(e);
            load_selective_broadcasts_support(e);
            load_e2e(e);
            load_debounce(e);
            load_acceptances(e);
            load_secure_services(e);
            load_partitions(e);
            load_routing_client_ports(e);
            load_suppress_events(e);
        }
    }

    return is_logging_loaded_ && has_routing && has_applications;
}

bool configuration_impl::load_logging(
        const configuration_element &_element, std::set<std::string> &_warnings) {
    try {
        auto its_logging = _element.tree_.get_child("logging");
        for (auto i = its_logging.begin(); i != its_logging.end(); ++i) {
            std::string its_key(i->first);
            if (its_key == "console") {
                if (is_configured_[ET_LOGGING_CONSOLE]) {
                    _warnings.insert("Multiple definitions for logging.console."
                            " Ignoring definition from " + _element.name_);
                } else {
                    std::string its_value(i->second.data());
                    #ifndef ANDROID
                        has_console_log_ = (its_value == "true");
                    #else
                        has_console_log_ = true;
                    #endif
                    is_configured_[ET_LOGGING_CONSOLE] = true;
                }
            } else if (its_key == "file") {
                if (is_configured_[ET_LOGGING_FILE]) {
                    _warnings.insert("Multiple definitions for logging.file."
                            " Ignoring definition from " + _element.name_);
                } else {
                    for (auto j : i->second) {
                        std::string its_sub_key(j.first);
                        std::string its_sub_value(j.second.data());
                        if (its_sub_key == "enable") {
                            has_file_log_ = (its_sub_value == "true");
                        } else if (its_sub_key == "path") {
                            logfile_ = its_sub_value;
                        }
                    }
                    is_configured_[ET_LOGGING_FILE] = true;
                }
            } else if (its_key == "dlt") {
                if (is_configured_[ET_LOGGING_DLT]) {
                    _warnings.insert("Multiple definitions for logging.dlt."
                            " Ignoring definition from " + _element.name_);
                } else {
                    std::string its_value(i->second.data());
                    has_dlt_log_ = (its_value == "true");
                    is_configured_[ET_LOGGING_DLT] = true;
                }
            } else if (its_key == "level") {
                if (is_configured_[ET_LOGGING_LEVEL]) {
                    _warnings.insert("Multiple definitions for logging.level."
                            " Ignoring definition from " + _element.name_);
                } else {
                    std::string its_value(i->second.data());
                    std::lock_guard<std::mutex> lock(mutex_loglevel_);
                    loglevel_
                        = (its_value == "trace" ?
                                vsomeip_v3::logger::level_e::LL_VERBOSE :
                          (its_value == "debug" ?
                                  vsomeip_v3::logger::level_e::LL_DEBUG :
                          (its_value == "info" ?
                                  vsomeip_v3::logger::level_e::LL_INFO :
                          (its_value == "warning" ?
                                  vsomeip_v3::logger::level_e::LL_WARNING :
                          (its_value == "error" ?
                                  vsomeip_v3::logger::level_e::LL_ERROR :
                          (its_value == "fatal" ?
                                  vsomeip_v3::logger::level_e::LL_FATAL :
                                  vsomeip_v3::logger::level_e::LL_INFO))))));
                    is_configured_[ET_LOGGING_LEVEL] = true;
                }
            } else if (its_key == "version") {
                std::stringstream its_converter;
                for (auto j : i->second) {
                    std::string its_sub_key(j.first);
                    std::string its_sub_value(j.second.data());
                    if (its_sub_key == "enable") {
                        log_version_ = (its_sub_value == "true");
                    } else if (its_sub_key == "interval") {
                        its_converter << std::dec << its_sub_value;
                        its_converter >> log_version_interval_;
                    }
                }
            } else if (its_key == "memory_log_interval") {
                std::stringstream its_converter;
                its_converter << std::dec << i->second.data();
                its_converter >> log_memory_interval_;
                if (log_memory_interval_ > 0) {
                    log_memory_ = true;
                }
            } else if (its_key == "status_log_interval") {
                std::stringstream its_converter;
                its_converter << std::dec << i->second.data();
                its_converter >> log_status_interval_;
                if (log_status_interval_ > 0) {
                    log_status_ = true;
                }
            } else if (its_key ==  "statistics") {
                for (auto j : i->second) {
                    std::stringstream its_converter;
                    std::string its_sub_key(j.first);
                    std::string its_sub_value(j.second.data());
                    if (its_sub_key == "interval") {
                        its_converter << std::dec << its_sub_value;
                        its_converter >> statistics_interval_;
                        if (statistics_interval_ > 0) {
                            log_statistics_ = true;
                        }
                    } else if (its_sub_key == "min-frequency") {
                        its_converter << std::dec << its_sub_value;
                        its_converter >> statistics_min_freq_;
                    } else if (its_sub_key == "max-messages") {
                        its_converter << std::dec << its_sub_value;
                        its_converter >> statistics_max_messages_;
                    }
                }
            }
        }
    } catch (...) {
        return false;
    }
    return true;
}

bool
configuration_impl::load_routing(const configuration_element &_element) {
    try {
        auto its_routing = _element.tree_.get_child("routing");
        if (is_configured_[ET_ROUTING]) {
            VSOMEIP_WARNING << "Multiple definitions of routing."
                    << " Ignoring definition from " << _element.name_;
        } else {
            routing_.is_enabled_ =
                its_routing.get_optional<bool>("enabled").get_value_or(routing_.is_enabled_);

            bool is_loaded = load_routing_host(its_routing, _element.name_)
                    && load_routing_guests(its_routing);

            if (!is_loaded) {
                routing_.host_.name_ = its_routing.data();
            } else {
                if (routing_.guests_.unicast_.is_unspecified())
                    routing_.guests_.unicast_ = routing_.host_.unicast_;
                if (routing_.guests_.ports_.empty())
                    routing_.guests_.ports_[{ ANY_UID, ANY_GID }].emplace(31492, 31999);
            }

            // Try to validate the port configuration. Check whether a range
            // contains an even number of ports and whether its starting port
            // number fits to the configured routing host port. Correct both
            // cases by reducing the range, if necessary.
            std::set<std::pair<port_t, port_t> > its_invalid_ranges;
            std::set<std::pair<port_t, port_t> > its_corrected_ranges;
            for (auto &ug : routing_.guests_.ports_) {
                for (auto &r : ug.second) {
                    auto its_pair = std::make_pair(r.first, r.second);

                    bool is_even(((r.second - r.first + 1) % 2) == 0);

                    // If the routing host port is [un]even, the start number of the
                    // range shall also be [un]even.
                    bool is_matching((r.first % 2) == (routing_.host_.port_ % 2));
                    if (!is_matching) {
                        its_pair.first++;
                        if (is_even)
                            its_pair.second--;
                    } else if (!is_even) {
                        its_pair.second--;
                    }

                    if (!is_even || !is_matching) {
                        its_invalid_ranges.insert(r);
                        its_corrected_ranges.insert(its_pair);
                    }
                }

                for (const auto &r : its_invalid_ranges)
                    ug.second.erase(r);
                its_invalid_ranges.clear();

                for (const auto &r : its_corrected_ranges)
                    ug.second.insert(r);
                its_corrected_ranges.clear();
            }
            is_configured_[ET_ROUTING] = true;
        }
    } catch (...) {
        return false;
    }
    return true;
}

bool
configuration_impl::load_routing_host(const boost::property_tree::ptree &_tree,
        const std::string &_name) {

    try {
        bool has_uid(false), has_gid(false);
        uid_t its_uid;
        gid_t its_gid;
        auto its_host = _tree.get_child("host");
        for (auto i = its_host.begin(); i != its_host.end(); ++i) {
            std::string its_key(i->first);
            std::string its_value(i->second.data());
            if (its_key == "name") {
                routing_.host_.name_ = its_value;
            } else if (its_key == "uid" || its_key == "gid") {
                std::stringstream its_converter;
                if (its_value.find("0x") == 0) {
                    its_converter << std::hex << its_value;
                } else {
                    its_converter << std::dec << its_value;
                }
                if (its_key == "uid") {
                    its_converter >> its_uid;
                    has_uid = true;
                } else {
                    its_converter >> its_gid;
                    has_gid = true;
                }
            } else if (its_key == "unicast") {
                routing_.host_.unicast_
                    = boost::asio::ip::make_address(its_value);
            } else if (its_key == "port") {
                std::stringstream its_converter;
                if (its_value.find("0x") == 0) {
                    its_converter << std::hex << its_value;
                } else {
                    its_converter << std::dec << its_value;
                }
                its_converter >> routing_.host_.port_;
            }
        }

        if (has_uid && has_gid) {
            policy_manager_->set_routing_credentials(its_uid, its_gid, _name);
        }

    } catch (...) {
        return false;
    }
    return true;
}

bool
configuration_impl::load_routing_guests(const boost::property_tree::ptree &_tree) {

    try {
        auto its_guests = _tree.get_child("guests");
        for (auto i = its_guests.begin(); i != its_guests.end(); ++i) {
            std::string its_key(i->first);
            if (its_key == "unicast") {
                std::string its_value(i->second.data());
                routing_.guests_.unicast_
                    = boost::asio::ip::make_address(its_value);
            } else if (its_key == "ports") {
                load_routing_guest_ports(i->second);
            }
        }
    } catch (...) {
        // intentionally left empty
    }
    return true;
}

void
configuration_impl::load_routing_guest_ports(
        const boost::property_tree::ptree &_tree) {

    std::stringstream its_converter;

    for (auto its_range = _tree.begin();
            its_range != _tree.end(); ++its_range) {

        uid_t its_uid { ANY_UID };
        gid_t its_gid { ANY_GID };
        std::set<std::pair<port_t, port_t> > its_ranges;

        try {
            auto its_uid_value = its_range->second.get_child("uid").data();
            its_converter.str("");
            its_converter.clear();
            its_converter << its_uid_value;
            its_converter >> (its_uid_value.find("0x") == 0 ? std::hex : std::dec) >> its_uid;

            auto its_gid_value = its_range->second.get_child("gid").data();
            its_converter.str("");
            its_converter.clear();
            its_converter << its_gid_value;
            its_converter >> (its_gid_value.find("0x") == 0 ? std::hex : std::dec) >> its_gid;

            auto its_ranges_value = its_range->second.get_child("ranges");
            its_ranges = load_routing_guest_port_range(its_ranges_value);
        } catch (...) {
            its_ranges = load_routing_guest_port_range(its_range->second);
        }

        if (!its_ranges.empty())
            routing_.guests_.ports_[{ its_uid, its_gid }] = its_ranges;
    }
}

std::set< std::pair<port_t, port_t> >
configuration_impl::load_routing_guest_port_range(
        const boost::property_tree::ptree &_tree) const {

    std::stringstream its_converter;
    std::set< std::pair<port_t, port_t> > its_ranges;

    for (auto its_range = _tree.begin();
             its_range != _tree.end(); ++its_range) {

        port_t its_first_port { 0 };
        port_t its_last_port { 0 };

        for (auto its_element = its_range->second.begin();
                its_element != its_range->second.end(); ++its_element) {

            std::string its_key(its_element->first);
            std::string its_value(its_element->second.data());

            if (!its_value.empty()) {
                its_converter.str("");
                its_converter.clear();
                its_converter << (its_value.find("0x") == 0 ? std::hex : std::dec) << its_value;

                if (its_key == "first") {
                    its_converter >> its_first_port;
                } else if (its_key == "last") {
                    its_converter >> its_last_port;
                }
            }
        }

        if (its_first_port > 0 && its_last_port > 0)
            its_ranges.emplace(std::min(its_first_port, its_last_port),
                    std::max(its_first_port, its_last_port));
    }

    return its_ranges;
}

void
configuration_impl::load_routing_client_ports(const configuration_element &_element) {

    try {
        auto its_ports = _element.tree_.get_child("routing-client-ports");
        load_routing_guest_ports(its_ports);
    }
    catch (...) {
    }
}

bool
configuration_impl::load_applications(const configuration_element &_element) {
    try {
        auto its_applications = _element.tree_.get_child("applications");
        for (auto i = its_applications.begin();
                i != its_applications.end();
                ++i) {
            load_application_data(i->second, _element.name_);
        }
    } catch (...) {
        return false;
    }
    return true;
}

void configuration_impl::load_application_data(
        const boost::property_tree::ptree &_tree, const std::string &_file_name) {
    std::string its_name("");
    client_t its_id(VSOMEIP_CLIENT_UNSET);
    std::size_t its_max_dispatchers(VSOMEIP_MAX_DISPATCHERS);
    std::size_t its_max_dispatch_time(VSOMEIP_MAX_DISPATCH_TIME);
    std::size_t its_max_detached_thread_wait_time(VSOMEIP_MAX_WAIT_TIME_DETACHED_THREADS);
    std::size_t its_io_thread_count(VSOMEIP_DEFAULT_IO_THREAD_COUNT);
    std::size_t its_request_debounce_time(VSOMEIP_REQUEST_DEBOUNCE_TIME);
    std::map<plugin_type_e, std::set<std::string>> plugins;
    int its_io_thread_nice_level(VSOMEIP_DEFAULT_IO_THREAD_NICE_LEVEL);
    debounce_configuration_t its_debounces;
    bool has_session_handling(true);
    for (auto i = _tree.begin(); i != _tree.end(); ++i) {
        std::string its_key(i->first);
        std::string its_value(i->second.data());
        std::stringstream its_converter;
        if (its_key == "name") {
            its_name = its_value;
        } else if (its_key == "id") {
            if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
                its_converter << std::hex << its_value;
            } else {
                its_converter << std::dec << its_value;
            }
            its_converter >> its_id;
        } else if (its_key == "max_dispatchers") {
            its_converter << std::dec << its_value;
            its_converter >> its_max_dispatchers;
        } else if (its_key == "max_dispatch_time") {
            its_converter << std::dec << its_value;
            its_converter >> its_max_dispatch_time;
        } else if (its_key == "max_detached_thread_wait_time") {
            its_converter << std::dec << its_value;
            its_converter >> its_max_detached_thread_wait_time;
        } else if (its_key == "threads") {
            its_converter << std::dec << its_value;
            its_converter >> its_io_thread_count;
            if (its_io_thread_count == 0) {
                VSOMEIP_WARNING << "Min. number of threads per application is 1";
                its_io_thread_count = 1;
            } else if (its_io_thread_count > 255) {
                VSOMEIP_WARNING << "Max. number of threads per application is 255";
                its_io_thread_count = 255;
            }
        } else if (its_key == "io_thread_nice") {
            its_converter << std::dec << its_value;
            its_converter >> its_io_thread_nice_level;
        } else if (its_key == "request_debounce_time") {
            its_converter << std::dec << its_value;
            its_converter >> its_request_debounce_time;
            if (its_request_debounce_time > 10000) {
                VSOMEIP_WARNING << "Max. request debounce time is 10.000ms";
                its_request_debounce_time = 10000;
            }
        } else if (its_key == "plugins") {
            plugins = load_plugins(i->second, its_name);
        } else if (its_key == "debounce") {
            try {
                for (auto j = i->second.begin(); j != i->second.end(); ++j) {
                    load_service_debounce(j->second, its_debounces);
                }
            } catch (...) {
                // intentionally empty
            }
        } else if (its_key == "has_session_handling") {
            has_session_handling = (its_value != "false");
        }
    }
    if (its_name != "") {
        if (applications_.find(its_name) == applications_.end()) {
            if (its_id != VSOMEIP_CLIENT_UNSET) {
                if (!is_configured_client_id(its_id)) {
                    client_identifiers_.insert(its_id);
                } else {
                    VSOMEIP_ERROR << "Multiple applications are configured to use"
                            << " client identifier " << std::hex << its_id
                            << ". Ignoring the configuration for application "
                            << its_name;
                    its_id = VSOMEIP_CLIENT_UNSET;
                }
            }

            applications_[its_name] = {its_id,
                                       its_max_dispatchers,
                                       its_max_dispatch_time,
                                       its_max_detached_thread_wait_time,
                                       its_io_thread_count,
                                       its_request_debounce_time,
                                       plugins,
                                       its_io_thread_nice_level,
                                       its_debounces,
                                       has_session_handling};
        } else {
            VSOMEIP_WARNING << "Multiple configurations for application "
                    << its_name << ". Ignoring a configuration from "
                    << _file_name;
        }
    }
}

std::map<plugin_type_e, std::set<std::string>> configuration_impl::load_plugins(
        const boost::property_tree::ptree &_tree,
        const std::string &_application_name) {
    std::map<plugin_type_e, std::set<std::string>> its_plugins;
    std::string its_name("");
    std::string its_type;
    for (auto i = _tree.begin(); i != _tree.end(); ++i) {
        bool its_configured[ET_MAX] = { 0 };
        for (auto l = i->second.begin(); l != i->second.end(); ++l) {
            std::string its_inner_key(l->first);
            std::string its_inner_value(l->second.data());

            if (its_inner_key == "name") {
                if (its_configured[ET_PLUGIN_NAME]) {
                    VSOMEIP_WARNING << "Multiple definitions of plugins.name."
                            << " Ignoring definition from " << its_inner_value;
                } else {
                    its_name = its_inner_value;
                    its_configured[ET_PLUGIN_NAME] = true;
                }
            } else if (its_inner_key == "type") {
                if (its_configured[ET_PLUGIN_TYPE]) {
                    VSOMEIP_WARNING << "Multiple definitions of plugins.type."
                            << " Ignoring definition from " << its_inner_value;
                } else {
                    its_type = its_inner_value;
                    its_configured[ET_PLUGIN_TYPE] = true;
                }
            } else if (its_inner_key == "additional") {
                if (its_configured[ET_PLUGIN_NAME]) {
                    const boost::property_tree::ptree &its_additional_tree(l->second);
                    for (auto m = its_additional_tree.begin(); m!= its_additional_tree.end(); ++m) {
                        for (auto n = m->second.begin(); n != m->second.end(); ++n) {
                            std::string its_additional_inner_key(n->first);
                            std::string its_additional_inner_value(n->second.data());
                            plugins_additional_[_application_name][its_name]
                                               [its_additional_inner_key] =
                                                    its_additional_inner_value;
                        }
                    }
                }
            } else {
                //support old config format (type : name)
                plugin_config_data_t its_plugin_data = {
                        its_inner_value, its_inner_key };
                add_plugin(its_plugins, its_plugin_data, _application_name);
            }
        }

        if (its_configured[ET_PLUGIN_NAME] && its_configured[ET_PLUGIN_TYPE]) {
            plugin_config_data_t its_plugin_data = {
                    its_name, its_type };
            add_plugin(its_plugins, its_plugin_data, _application_name);
        }
    }

    return its_plugins;
}

void configuration_impl::add_plugin(std::map<plugin_type_e, std::set<std::string>> &_plugins,
        const plugin_config_data_t &_plugin_data,
        const std::string& _application_name) {

#ifdef _WIN32
    std::string its_library(_plugin_data.name_);
    its_library += ".dll";
#else
    std::string its_library("lib");
    its_library += _plugin_data.name_;
    its_library += ".so";
#endif

    if (_plugin_data.type_ == "application_plugin") {
#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
        its_library += ".";
        its_library += (VSOMEIP_APPLICATION_PLUGIN_VERSION + '0');
#endif
        _plugins[plugin_type_e::APPLICATION_PLUGIN].insert(its_library);
    } else if (_plugin_data.type_ == "configuration_plugin") {
#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
        its_library += ".";
        its_library += (VSOMEIP_PRE_CONFIGURATION_PLUGIN_VERSION + '0');
#endif
        _plugins[plugin_type_e::PRE_CONFIGURATION_PLUGIN].insert(its_library);
    } else {
        VSOMEIP_WARNING << "Unknown plug-in type ("
            << _plugin_data.type_ << ") configured for client: "
            << _application_name;
    }
}

void configuration_impl::load_tracing(const configuration_element &_element) {
    try {
        auto its_trace_configuration = _element.tree_.get_child("tracing");
        for(auto i = its_trace_configuration.begin();
                i != its_trace_configuration.end();
                ++i) {
            std::string its_key(i->first);
            std::string its_value(i->second.data());
            if(its_key == "enable") {
                if (is_configured_[ET_TRACING_ENABLE]) {
                    VSOMEIP_WARNING << "Multiple definitions of tracing.enable."
                            << " Ignoring definition from " << _element.name_;
                } else {
                    trace_->is_enabled_ = (its_value == "true");
                    is_configured_[ET_TRACING_ENABLE] = true;
                }
            } else if (its_key == "sd_enable") {
                if (is_configured_[ET_TRACING_SD_ENABLE]) {
                    VSOMEIP_WARNING << "Multiple definitions of tracing.sd_enable."
                            << " Ignoring definition from " << _element.name_;
                } else {
                    trace_->is_sd_enabled_ = (its_value == "true");
                    is_configured_[ET_TRACING_SD_ENABLE] = true;
                }
            } else if(its_key == "channels") {
                load_trace_channels(i->second);
            } else if(its_key == "filters") {
                load_trace_filters(i->second);
            }
        }
    } catch (...) {
        // intentionally left empty
    }
}

void configuration_impl::load_trace_channels(
        const boost::property_tree::ptree &_tree) {
    try {
        for(auto i = _tree.begin(); i != _tree.end(); ++i) {
            if(i == _tree.begin())
                trace_->channels_.clear();
            load_trace_channel(i->second);
        }
    } catch (...) {
        // intentionally left empty
    }
}

void configuration_impl::load_trace_channel(
        const boost::property_tree::ptree &_tree) {
    auto its_channel = std::make_shared<trace_channel>();
    for(auto i = _tree.begin(); i != _tree.end(); ++i) {
        std::string its_key = i->first;
        std::string its_value = i->second.data();
        if(its_key == "name") {
            its_channel->name_ = its_value;
        } else if(its_key == "id") {
            its_channel->id_ = its_value;
        }
    }
    trace_->channels_.push_back(its_channel);
}

void configuration_impl::load_trace_filters(
        const boost::property_tree::ptree &_tree) {
    try {
        for(auto i = _tree.begin(); i != _tree.end(); ++i) {
            load_trace_filter(i->second);
        }
    } catch (...) {
        // intentionally left empty
    }
}

void configuration_impl::load_trace_filter(
        const boost::property_tree::ptree &_tree) {
    auto its_filter = std::make_shared<trace_filter>();
    bool has_channel(false);
    for (auto i = _tree.begin(); i != _tree.end(); ++i) {
        std::string its_key = i->first;
        if (its_key == "channel") {
            std::string its_value;
            if (i->second.size() == 0) {
                its_value = i->second.data();
                its_filter->channels_.push_back(its_value);
            } else {
                for (auto j = i->second.begin(); j != i->second.end(); ++j) {
                    its_filter->channels_.push_back(j->second.data());
                }
            }
            has_channel = true;
        } else if(its_key == "type") {
            std::string its_value = i->second.data();
            if (its_value == "negative")
                its_filter->ftype_ = vsomeip_v3::trace::filter_type_e::NEGATIVE;
            else if (its_value == "header-only")
                its_filter->ftype_ = vsomeip_v3::trace::filter_type_e::HEADER_ONLY;
            else
                its_filter->ftype_ = vsomeip_v3::trace::filter_type_e::POSITIVE;
        } else {
            load_trace_filter_expressions(i->second, its_key, its_filter);
        }
    }

    if (!has_channel) {
        its_filter->channels_.push_back("TC"); // default
    }

    if (!its_filter->is_range_ || its_filter->matches_.size() > 0) {
        trace_->filters_.push_back(its_filter);
    }
}

void configuration_impl::load_trace_filter_expressions(
        const boost::property_tree::ptree &_tree,
        std::string &_criteria,
        std::shared_ptr<trace_filter> &_filter) {
    if (_criteria == "services") {
        for (auto i = _tree.begin(); i != _tree.end(); ++i) {
            vsomeip_v3::trace::match_t its_match;
            load_trace_filter_match(i->second, its_match);
            _filter->matches_.push_back(its_match);
        }
    } else if (_criteria == "methods") {
        if (!has_issued_methods_warning_) {
            VSOMEIP_WARNING << "\"method\" entry in filter configuration has no effect!";
            has_issued_methods_warning_ = true;
        }
    } else if (_criteria == "clients") {
        if (!has_issued_clients_warning_) {
            VSOMEIP_WARNING << "\"clients\" entry in filter configuration has no effect!";
            has_issued_clients_warning_ = true;
        }
    } else if (_criteria == "matches") {
        for (auto i = _tree.begin(); i != _tree.end(); ++i) {
            vsomeip_v3::trace::match_t its_match;
            load_trace_filter_match(i->second, its_match);
            if (i->first == "from") {
                _filter->is_range_ = true;
                _filter->matches_.insert(_filter->matches_.begin(), its_match);
            } else {
                if (i->first == "to") _filter->is_range_ = true;
                _filter->matches_.push_back(its_match);
            }
        }
    }
}

void configuration_impl::load_trace_filter_match(
        const boost::property_tree::ptree &_data,
        vsomeip_v3::trace::match_t &_match) {
    std::stringstream its_converter;

    if (_data.size() == 0) {
        const std::string& its_value(_data.data());
        service_t its_service(ANY_SERVICE);
        if (its_value.find("0x") == 0) {
            its_converter << std::hex << its_value;
        } else {
            its_converter << std::dec << its_value;
        }
        its_converter >> its_service;

        std::get<0>(_match) = its_service;
        std::get<1>(_match) = ANY_INSTANCE;
        std::get<2>(_match) = ANY_METHOD;
    } else {
        std::get<0>(_match) = ANY_SERVICE;
        std::get<1>(_match) = ANY_INSTANCE;
        std::get<2>(_match) = ANY_METHOD;

        for (auto i = _data.begin(); i != _data.end(); ++i) {
            std::string its_value;

            its_converter.str("");
            its_converter.clear();

            try {
                its_value = i->second.data();
                if (its_value == "any") its_value = "0xffff";

                if (i->first == "service") {
                    service_t its_service(ANY_SERVICE);
                    if (its_value.find("0x") == 0) {
                        its_converter << std::hex << its_value;
                    } else {
                        its_converter << std::dec << its_value;
                    }
                    its_converter >> its_service;
                    std::get<0>(_match) = its_service;
                } else if (i->first == "instance") {
                    instance_t its_instance(ANY_INSTANCE);
                    if (its_value.find("0x") == 0) {
                        its_converter << std::hex << its_value;
                    } else {
                        its_converter << std::dec << its_value;
                    }
                    its_converter >> its_instance;
                    std::get<1>(_match) = its_instance;
                } else if (i->first == "method") {
                    method_t its_method(ANY_METHOD);
                    if (its_value.find("0x") == 0) {
                        its_converter << std::hex << its_value;
                    } else {
                        its_converter << std::dec << its_value;
                    }
                    its_converter >> its_method;
                    std::get<2>(_match) = its_method;
                }
            } catch (...) {
                // Intentionally left empty
            }
        }
    }
}

void configuration_impl::load_suppress_events(const configuration_element &_element) {
    try {
        auto its_missing_events = _element.tree_.get_child("suppress_missing_event_logs");

        if(its_missing_events.size()) {
            for (auto i = its_missing_events.begin();
                    i != its_missing_events.end();
                    ++i) {
                load_suppress_events_data(i->second);
            }

            if(suppress_events_.size())
                is_suppress_events_enabled_ = true;
        }
    } catch (...) {
                // Intentionally left empty
    }
}

void configuration_impl::load_suppress_events_data(
        const boost::property_tree::ptree &_tree) {

    //Default everything to ANY, and change with the provided values
    service_t its_service(ANY_SERVICE);
    instance_t its_instance(ANY_INSTANCE);
    event_t its_event(ANY_EVENT);
    std::set<event_t> events;

    for (auto i = _tree.begin(); i != _tree.end(); ++i) {
        std::string its_key(i->first);
        std::string its_value(i->second.data());
        std::stringstream its_converter;

        if (its_key == "service") {
            its_service = load_suppress_data(its_value);
        } else if (its_key == "instance") {
            its_instance = load_suppress_data(its_value);
        } else if (its_key == "events") {
            if (i->second.empty()) {    //Single Event
                its_event = load_suppress_data(its_value);
                events.insert(its_event);
            } else {                        //Multiple Events/Range
                events = load_suppress_multiple_events(i->second);
            }
        }
    }

    //If no event is present in the configuration, use ANY_EVENT!
    if(events.empty())
        events.insert(ANY_EVENT);

    for(const auto& event : events) {
        insert_suppress_events(its_service, its_instance, event);
    }
}

std::set<event_t> configuration_impl::load_suppress_multiple_events(
        const boost::property_tree::ptree &_tree) {

    event_t its_first_event(ANY_EVENT);
    event_t its_last_event(ANY_EVENT);
    event_t its_event(ANY_EVENT);
    std::set<event_t> events;

    try {
        for(auto i = _tree.begin(); i != _tree.end(); ++i) {
            std::string its_key(i->first);
            std::string its_value(i->second.data());

            //Extract Single Event from multiple entries
            if (i->second.size() == 0) {

                if (its_key == "first") {   // Range Events
                    its_first_event = load_suppress_data(its_value);
                } else if (its_key == "last") {
                    its_last_event = load_suppress_data(its_value);

                    std::set<event_t> range_events = load_range_events(its_first_event, its_last_event);
                    events.insert(range_events.begin(), range_events.end());
                    return events;
                } else {
                    //Single Events
                    its_event = load_suppress_data(its_value);
                    events.insert(its_event);
                }
            } else {
                //Go down one level in the JSON, recursively
                std::set<event_t> range_events = load_suppress_multiple_events(i->second);
                events.insert(range_events.begin(), range_events.end());
            }
        }
    } catch (...) {
        // intentionally left empty
    }
    return events;
}

uint16_t configuration_impl::load_suppress_data(const std::string &_value) const {

    std::stringstream its_converter;
    uint16_t its_converted = ANY_EVENT;

    if (_value == "any") {
        its_converted = ANY_EVENT;         //use ANY_x
    } else if (_value.find("0x") == 0) {
        its_converter << std::hex << _value;
    } else {
        its_converter << std::dec << _value;
    }
    its_converter >> its_converted;

    return its_converted;
}

std::set<event_t> configuration_impl::load_range_events(event_t _first_event,
    event_t _last_event) const {

    std::set<event_t> range_events;

    if ((_first_event != ANY_EVENT) && (_last_event != ANY_EVENT)) {
        for (event_t its_event = _first_event; its_event<=_last_event; its_event++) {
            range_events.insert(its_event);
        }
    }
    return range_events;
}

void configuration_impl::insert_suppress_events(service_t  _service,
    instance_t _instance, event_t _event) {

    suppress_t new_event = {_service, _instance, _event};
    suppress_events_.insert(new_event);
}

bool configuration_impl::check_suppress_events(service_t _service, instance_t _instance,
        event_t _event) const {

    if (!is_suppress_events_enabled_)
        return false;

    std::set<suppress_t> event_combinations = {
        {_service, _instance, _event},
        {_service, _instance, ANY_EVENT},
        {_service, ANY_INSTANCE, _event},
        {_service, ANY_INSTANCE, ANY_EVENT},
        {ANY_SERVICE, _instance, _event},
        {ANY_SERVICE, _instance, ANY_EVENT},
        {ANY_SERVICE, ANY_INSTANCE, _event}
        };

    for (const auto &its_event: event_combinations) {
        if (suppress_events_.find(its_event) != std::end(suppress_events_))
            return true;
    }

    return false;
}

void configuration_impl::print_suppress_events(void) const {

    VSOMEIP_INFO << "Suppress Event logs size: " << suppress_events_.size();

    for (const auto& its_log : suppress_events_) {
        VSOMEIP_INFO << std::hex << std::setfill('0')
                    << "+[" << std::setw(4) << its_log.service
                    << "." << std::setw(4) << its_log.instance
                    << "." << its_log.event << "]";
    }
}

void configuration_impl::load_unicast_address(const configuration_element &_element) {
    try {
        std::string its_value = _element.tree_.get<std::string>("unicast");
        if (is_configured_[ET_UNICAST]) {
            VSOMEIP_WARNING << "Multiple definitions for unicast."
                    "Ignoring definition from " << _element.name_;
        } else {
            unicast_ = unicast_.from_string(its_value);
            is_configured_[ET_UNICAST] = true;
        }
    } catch (...) {
        // intentionally left empty!
    }
}

void configuration_impl::load_netmask(const configuration_element &_element) {
    try {
        auto its_value = _element.tree_.get_optional<std::string>("netmask");
        if (its_value) {
            if (is_configured_[ET_NETMASK]) {
                VSOMEIP_WARNING << "Multiple definitions for netmask/prefix."
                        "Ignoring netmask definition from " << _element.name_;
            } else {
                netmask_ = netmask_.from_string(*its_value);
                is_configured_[ET_NETMASK] = true;
            }
        }

        its_value = _element.tree_.get_optional<std::string>("prefix");
        if (its_value) {
            if (is_configured_[ET_NETMASK]) {
                VSOMEIP_WARNING << "Multiple definitions for prefix/netmask."
                        "Ignoring prefix definition from " << _element.name_;
            } else {
                std::stringstream its_converter;
                its_converter << *its_value;
                its_converter >> std::dec >> prefix_;

                // Convert to netmask as this is used for IPv4.
                uint32_t its_netmask = (std::numeric_limits<uint32_t>::max()
                    << (std::numeric_limits<uint32_t>::digits - prefix_))
                            & std::numeric_limits<uint32_t>::max();
                netmask_ = boost::asio::ip::address_v4(its_netmask);

                is_configured_[ET_NETMASK] = true;
            }
        }
    } catch (...) {
        // intentionally left empty!
    }
}

void configuration_impl::load_device(const configuration_element &_element) {
    try {
        std::string its_value = _element.tree_.get<std::string>("device");
        if (is_configured_[ET_DEVICE]) {
            VSOMEIP_WARNING << "Multiple definitions for device."
                    "Ignoring definition from " << _element.name_;
        } else {
            device_ = its_value;
            is_configured_[ET_DEVICE] = true;
        }
    } catch (...) {
        // intentionally left empty!
    }
}

void configuration_impl::load_network(const configuration_element &_element) {
    try {
        std::string its_value(_element.tree_.get<std::string>("network"));
        if (is_configured_[ET_NETWORK]) {
            VSOMEIP_WARNING << "Multiple definitions for network."
                    "Ignoring definition from " << _element.name_;
        } else {
            network_ = its_value;
            is_configured_[ET_NETWORK] = true;
        }
    } catch (...) {
        // intentionally left empty
    }
}

void configuration_impl::load_diagnosis_address(const configuration_element &_element) {
    try {
        std::string its_value = _element.tree_.get<std::string>("diagnosis");
        if (is_configured_[ET_DIAGNOSIS]) {
            VSOMEIP_WARNING << "Multiple definitions for diagnosis."
                    "Ignoring definition from " << _element.name_;
        } else {
            std::stringstream its_converter;

            if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
                its_converter << std::hex << its_value;
            } else {
                its_converter << std::dec << its_value;
            }
            its_converter >> diagnosis_;
            is_configured_[ET_DIAGNOSIS] = true;
        }
        std::string its_mask = _element.tree_.get<std::string>("diagnosis_mask");
        if (is_configured_[ET_DIAGNOSIS_MASK]) {
            VSOMEIP_WARNING << "Multiple definitions for diagnosis_mask."
                    "Ignoring definition from " << _element.name_;
        } else {
            std::stringstream its_converter;

            if (its_mask.size() > 1 && its_mask[0] == '0' && its_mask[1] == 'x') {
                its_converter << std::hex << its_mask;
            } else {
                its_converter << std::dec << its_mask;
            }
            its_converter >> diagnosis_mask_;
            is_configured_[ET_DIAGNOSIS_MASK] = true;
        }
        if (is_configured_[ET_DIAGNOSIS] && is_configured_[ET_DIAGNOSIS_MASK]
               && (static_cast<std::uint16_t>(diagnosis_ << 8) & diagnosis_mask_)
                   != static_cast<std::uint16_t>(diagnosis_ << 8)) {
            VSOMEIP_WARNING << "Diagnosis mask masks bits of diagnosis prefix! "
                    "Client IDs will start at 0x" << std::hex <<
                    (static_cast<std::uint16_t>(diagnosis_ << 8) & diagnosis_mask_)
                    << " not at 0x" << static_cast<std::uint16_t>(diagnosis_ << 8);
        }
    } catch (...) {
        // intentionally left empty
    }
}

void configuration_impl::load_shutdown_timeout(const configuration_element &_element) {
    const std::string shutdown_timeout("shutdown_timeout");
    try {
        if (_element.tree_.get_child_optional(shutdown_timeout)) {
            std::string its_value = _element.tree_.get<std::string>("shutdown_timeout");
            if (is_configured_[ET_SHUTDOWN_TIMEOUT]) {
                VSOMEIP_WARNING << "Multiple definitions for shutdown_timeout."
                        "Ignoring definition from " << _element.name_;
            } else {
                std::stringstream its_converter;

                if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
                    its_converter << std::hex << its_value;
                } else {
                    its_converter << std::dec << its_value;
                }
                its_converter >> shutdown_timeout_;
                is_configured_[ET_SHUTDOWN_TIMEOUT] = true;
            }
        }
    } catch (...) {
        // intentionally left empty
    }
}

void configuration_impl::load_service_discovery(
        const configuration_element &_element) {
    try {
        auto its_service_discovery = _element.tree_.get_child("service-discovery");
        for (auto i = its_service_discovery.begin();
                i != its_service_discovery.end(); ++i) {
            std::string its_key(i->first);
            std::string its_value(i->second.data());
            std::stringstream its_converter;
            if (its_key == "enable") {
                if (is_configured_[ET_SERVICE_DISCOVERY_ENABLE]) {
                    VSOMEIP_WARNING << "Multiple definitions for service_discovery.enabled."
                            " Ignoring definition from " << _element.name_;
                } else {
                    is_sd_enabled_ = (its_value == "true");
                    is_configured_[ET_SERVICE_DISCOVERY_ENABLE] = true;
                }
            } else if (its_key == "multicast") {
                if (is_configured_[ET_SERVICE_DISCOVERY_MULTICAST]) {
                    VSOMEIP_WARNING << "Multiple definitions for service_discovery.multicast."
                            " Ignoring definition from " << _element.name_;
                } else {
                    sd_multicast_ = its_value;
                    is_configured_[ET_SERVICE_DISCOVERY_MULTICAST] = true;
                }
            } else if (its_key == "port") {
                if (is_configured_[ET_SERVICE_DISCOVERY_PORT]) {
                    VSOMEIP_WARNING << "Multiple definitions for service_discovery.port."
                            " Ignoring definition from " << _element.name_;
                } else {
                    its_converter << its_value;
                    its_converter >> sd_port_;
                    if (!sd_port_) {
                        sd_port_ = VSOMEIP_SD_DEFAULT_PORT;
                    } else {
                        is_configured_[ET_SERVICE_DISCOVERY_PORT] = true;
                    }
                }
            } else if (its_key == "protocol") {
                if (is_configured_[ET_SERVICE_DISCOVERY_PROTOCOL]) {
                    VSOMEIP_WARNING << "Multiple definitions for service_discovery.protocol."
                            " Ignoring definition from " << _element.name_;
                } else {
                    sd_protocol_ = its_value;
                    is_configured_[ET_SERVICE_DISCOVERY_PROTOCOL] = true;
                }
            } else if (its_key == "initial_delay_min") {
                if (is_configured_[ET_SERVICE_DISCOVERY_INITIAL_DELAY_MIN]) {
                    VSOMEIP_WARNING << "Multiple definitions for service_discovery.initial_delay_min."
                            " Ignoring definition from " << _element.name_;
                } else {
                    its_converter << its_value;
                    its_converter >> sd_initial_delay_min_;
                    is_configured_[ET_SERVICE_DISCOVERY_INITIAL_DELAY_MIN] = true;
                }
            } else if (its_key == "initial_delay_max") {
                if (is_configured_[ET_SERVICE_DISCOVERY_INITIAL_DELAY_MAX]) {
                    VSOMEIP_WARNING << "Multiple definitions for service_discovery.initial_delay_max."
                            " Ignoring definition from " << _element.name_;
                } else {
                    its_converter << its_value;
                    its_converter >> sd_initial_delay_max_;
                    is_configured_[ET_SERVICE_DISCOVERY_INITIAL_DELAY_MAX] = true;
                }
            } else if (its_key == "repetitions_base_delay") {
                if (is_configured_[ET_SERVICE_DISCOVERY_REPETITION_BASE_DELAY]) {
                    VSOMEIP_WARNING << "Multiple definitions for service_discovery.repetition_base_delay."
                            " Ignoring definition from " << _element.name_;
                } else {
                    its_converter << its_value;
                    its_converter >> sd_repetitions_base_delay_;
                    is_configured_[ET_SERVICE_DISCOVERY_REPETITION_BASE_DELAY] = true;
                }
            } else if (its_key == "repetitions_max") {
                if (is_configured_[ET_SERVICE_DISCOVERY_REPETITION_MAX]) {
                    VSOMEIP_WARNING << "Multiple definitions for service_discovery.repetition_max."
                            " Ignoring definition from " << _element.name_;
                } else {
                    int tmp;
                    its_converter << its_value;
                    its_converter >> tmp;
                    sd_repetitions_max_ = (tmp > std::numeric_limits<std::uint8_t>::max()) ?
                                    std::numeric_limits<std::uint8_t>::max() :
                                    static_cast<std::uint8_t>(tmp);
                    is_configured_[ET_SERVICE_DISCOVERY_REPETITION_MAX] = true;
                }
            } else if (its_key == "ttl") {
                if (is_configured_[ET_SERVICE_DISCOVERY_TTL]) {
                    VSOMEIP_WARNING << "Multiple definitions for service_discovery.ttl."
                            " Ignoring definition from " << _element.name_;
                } else {
                    its_converter << its_value;
                    its_converter >> sd_ttl_;
                    // We do _not_ accept 0 as this would mean "STOP OFFER"
                    if (sd_ttl_ == 0) {
                        VSOMEIP_WARNING << "TTL=0 is not allowed. Using default ("
                                << std::dec << VSOMEIP_SD_DEFAULT_TTL << ")";
                        sd_ttl_ = VSOMEIP_SD_DEFAULT_TTL;
                    }
                    else is_configured_[ET_SERVICE_DISCOVERY_TTL] = true;
                }
            } else if (its_key == "cyclic_offer_delay") {
                if (is_configured_[ET_SERVICE_DISCOVERY_CYCLIC_OFFER_DELAY]) {
                    VSOMEIP_WARNING << "Multiple definitions for service_discovery.cyclic_offer_delay."
                            " Ignoring definition from " << _element.name_;
                } else {
                    its_converter << its_value;
                    its_converter >> sd_cyclic_offer_delay_;
                    is_configured_[ET_SERVICE_DISCOVERY_CYCLIC_OFFER_DELAY] = true;
                }
            } else if (its_key == "request_response_delay") {
                if (is_configured_[ET_SERVICE_DISCOVERY_REQUEST_RESPONSE_DELAY]) {
                    VSOMEIP_WARNING << "Multiple definitions for service_discovery.request_response_delay."
                            " Ignoring definition from " << _element.name_;
                } else {
                    its_converter << its_value;
                    its_converter >> sd_request_response_delay_;
                    is_configured_[ET_SERVICE_DISCOVERY_REQUEST_RESPONSE_DELAY] = true;
                }
            } else if (its_key == "offer_debounce_time") {
                if (is_configured_[ET_SERVICE_DISCOVERY_OFFER_DEBOUNCE_TIME]) {
                    VSOMEIP_WARNING << "Multiple definitions for service_discovery.offer_debounce."
                    " Ignoring definition from " << _element.name_;
                } else {
                    its_converter << its_value;
                    its_converter >> sd_offer_debounce_time_;
                    is_configured_[ET_SERVICE_DISCOVERY_OFFER_DEBOUNCE_TIME] = true;
                }
            } else if (its_key == "find_debounce_time") {
                if (is_configured_[ET_SERVICE_DISCOVERY_FIND_DEBOUNCE_TIME]) {
                    VSOMEIP_WARNING << "Multiple definitions for service_discovery.find_debounce."
                    " Ignoring definition from " << _element.name_;
                } else {
                    its_converter << its_value;
                    its_converter >> sd_find_debounce_time_;
                    is_configured_[ET_SERVICE_DISCOVERY_FIND_DEBOUNCE_TIME] = true;
                }
            } else if (its_key == "ttl_factor_offers") {
                if (is_configured_[ET_SERVICE_DISCOVERY_TTL_FACTOR_OFFERS]) {
                    VSOMEIP_WARNING << "Multiple definitions for service_discovery.ttl_factor_offers."
                    " Ignoring definition from " << _element.name_;
                } else {
                    load_ttl_factors(i->second, &ttl_factors_offers_);
                    is_configured_[ET_SERVICE_DISCOVERY_TTL_FACTOR_OFFERS] = true;
                }
            } else if (its_key == "ttl_factor_subscriptions") {
                if (is_configured_[ET_SERVICE_DISCOVERY_TTL_FACTOR_SUBSCRIPTIONS]) {
                    VSOMEIP_WARNING << "Multiple definitions for service_discovery.ttl_factor_subscriptions."
                    " Ignoring definition from " << _element.name_;
                } else {
                    load_ttl_factors(i->second, &ttl_factors_subscriptions_);
                    is_configured_[ET_SERVICE_DISCOVERY_TTL_FACTOR_SUBSCRIPTIONS] = true;
                }
            } else if (its_key == "max_remote_subscribers") {
                if (is_configured_[ET_MAX_REMOTE_SUBSCRIBERS]) {
                    VSOMEIP_WARNING << "Multiple definitions for service_discovery.max_remote_subscribers."
                    " Ignoring definition from " << _element.name_;
                } else {
                    int tmp;
                    its_converter << its_value;
                    its_converter >> tmp;
                    max_remote_subscribers_ = (tmp > std::numeric_limits<std::uint8_t>::max()) ?
                                    std::numeric_limits<std::uint8_t>::max() :
                                    static_cast<std::uint8_t>(tmp);
                    if (max_remote_subscribers_ == 0) {
                        VSOMEIP_WARNING << "max_remote_subscribers_ = 0 is not allowed. Using default ("
                                << std::dec << VSOMEIP_DEFAULT_MAX_REMOTE_SUBSCRIBERS << ")";
                        max_remote_subscribers_ = VSOMEIP_DEFAULT_MAX_REMOTE_SUBSCRIBERS;
                    }
                    is_configured_[ET_MAX_REMOTE_SUBSCRIBERS] = true;
                }
            }
        }
    } catch (...) {
    }
}

void configuration_impl::load_delays(
        const boost::property_tree::ptree &_tree) {
    try {
        std::stringstream its_converter;
        for (auto i = _tree.begin(); i != _tree.end(); ++i) {
            std::string its_key(i->first);
            if (its_key == "initial") {
                sd_initial_delay_min_ = i->second.get<uint32_t>("minimum");
                sd_initial_delay_max_ = i->second.get<uint32_t>("maximum");
            } else if (its_key == "repetition-base") {
                its_converter << std::dec << i->second.data();
                its_converter >> sd_repetitions_base_delay_;
            } else if (its_key == "repetition-max") {
                int tmp_repetition_max;
                its_converter << std::dec << i->second.data();
                its_converter >> tmp_repetition_max;
                sd_repetitions_max_ =
                        (tmp_repetition_max
                                > std::numeric_limits<std::uint8_t>::max()) ?
                                        std::numeric_limits<std::uint8_t>::max() :
                                        static_cast<std::uint8_t>(tmp_repetition_max);
            } else if (its_key == "cyclic-offer") {
                its_converter << std::dec << i->second.data();
                its_converter >> sd_cyclic_offer_delay_;
            } else if (its_key == "cyclic-request") {
                its_converter << std::dec << i->second.data();
                its_converter >> sd_request_response_delay_;
            } else if (its_key == "ttl") {
                its_converter << std::dec << i->second.data();
                its_converter >> sd_ttl_;
            }
            its_converter.str("");
            its_converter.clear();
        }
    } catch (...) {
    }
}

void configuration_impl::load_npdu_default_timings(const configuration_element &_element) {
    const std::string ndt("npdu-default-timings");
    const std::string dreq("debounce-time-request");
    const std::string dres("debounce-time-response");
    const std::string rreq("max-retention-time-request");
    const std::string rresp("max-retention-time-response");
    try {
        if (_element.tree_.get_child_optional(ndt)) {
            if (is_configured_[ET_NPDU_DEFAULT_TIMINGS]) {
                VSOMEIP_WARNING << "Multiple definitions of " << ndt
                        << " Ignoring definition from " << _element.name_;
            } else {
                for (const auto& e : _element.tree_.get_child(ndt)) {
                    std::chrono::nanoseconds its_time(0);
                    try {
                        its_time = std::chrono::nanoseconds(
                                std::strtoull(e.second.data().c_str(), NULL, 10)
                                * 1000000);
                    } catch (const std::exception&) {
                        continue;
                    }
                    if (e.first.data() == dreq) {
                        npdu_default_debounce_requ_ = its_time;
                    } else if (e.first.data() == dres) {
                        npdu_default_debounce_resp_ = its_time;
                    } else if (e.first.data() == rreq) {
                        npdu_default_max_retention_requ_ = its_time;
                    } else if (e.first.data() == rresp) {
                        npdu_default_max_retention_resp_ = its_time;
                    }
                }
                is_configured_[ET_NPDU_DEFAULT_TIMINGS] = true;
            }
        }
    } catch (...) {
        // intentionally left empty
    }
}

void configuration_impl::load_services(const configuration_element &_element) {
    std::lock_guard<std::mutex> its_lock(services_mutex_);
    try {
        auto its_services = _element.tree_.get_child("services");
        for (auto i = its_services.begin(); i != its_services.end(); ++i)
            load_service(i->second, default_unicast_);
    } catch (...) {
        try {
            auto its_servicegroups = _element.tree_.get_child("servicegroups");
            for (auto i = its_servicegroups.begin(); i != its_servicegroups.end(); ++i)
                load_servicegroup(i->second);
        } catch (...) {
            // intentionally left empty
        }
    }
}

void configuration_impl::load_servicegroup(
        const boost::property_tree::ptree &_tree) {
    try {
        std::string its_unicast_address(default_unicast_);

        for (auto i = _tree.begin(); i != _tree.end(); ++i) {
            std::string its_key(i->first);
            if (its_key == "unicast") {
                its_unicast_address = i->second.data();
                break;
            }
        }

        for (auto i = _tree.begin(); i != _tree.end(); ++i) {
            std::string its_key(i->first);
            if (its_key == "delays") {
                load_delays(i->second);
            } else if (its_key == "services") {
                for (auto j = i->second.begin(); j != i->second.end(); ++j)
                    load_service(j->second, its_unicast_address);
            }
        }
    } catch (...) {
        // Intentionally left empty
    }
}

void configuration_impl::load_service(
        const boost::property_tree::ptree &_tree,
        const std::string &_unicast_address) {
    try {
        bool is_loaded(true);
        bool use_magic_cookies(false);

        auto its_service = std::make_shared<service>();
        its_service->reliable_ = its_service->unreliable_ = ILLEGAL_PORT;
        its_service->unicast_address_ = _unicast_address;
        its_service->multicast_address_ = "";
        its_service->multicast_port_ = ILLEGAL_PORT;
        its_service->protocol_ = "someip";

        for (auto i = _tree.begin(); i != _tree.end(); ++i) {
            std::string its_key(i->first);
            std::string its_value(i->second.data());
            std::stringstream its_converter;

            if (its_key == "unicast") {
                its_service->unicast_address_ = its_value;
            } else if (its_key == "reliable") {
                try {
                    its_value = i->second.get_child("port").data();
                    its_converter << its_value;
                    its_converter >> its_service->reliable_;
                } catch (...) {
                    its_converter << its_value;
                    its_converter >> its_service->reliable_;
                }
                if(!its_service->reliable_) {
                    its_service->reliable_ = ILLEGAL_PORT;
                }
                try {
                    its_value
                        = i->second.get_child("enable-magic-cookies").data();
                    use_magic_cookies = ("true" == its_value);
                } catch (...) {

                }
            } else if (its_key == "unreliable") {
                its_converter << its_value;
                its_converter >> its_service->unreliable_;
                if(!its_service->unreliable_) {
                    its_service->unreliable_ = ILLEGAL_PORT;
                }
            } else if (its_key == "multicast") {
                try {
                    its_value = i->second.get_child("address").data();
                    its_service->multicast_address_ = its_value;
                    its_value = i->second.get_child("port").data();
                    its_converter << its_value;
                    its_converter >> its_service->multicast_port_;
                } catch (...) {
                }
            } else if (its_key == "protocol") {
                its_service->protocol_ = its_value;
            } else if (its_key == "events") {
                load_event(its_service, i->second);
            } else if (its_key == "eventgroups") {
                load_eventgroup(its_service, i->second);
            } else if (its_key == "debounce-times") {
                load_npdu_debounce_times_configuration(its_service, i->second);
            } else if (its_key == "someip-tp") {
                load_someip_tp(its_service, i->second);
            } else {
                // Trim "its_value"
                if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
                    its_converter << std::hex << its_value;
                } else {
                    its_converter << std::dec << its_value;
                }

                if (its_key == "service") {
                    its_converter >> its_service->service_;
                } else if (its_key == "instance") {
                    its_converter >> its_service->instance_;
                }
            }
        }

        auto found_service = services_.find(its_service->service_);
        if (found_service != services_.end()) {
            auto found_instance = found_service->second.find(
                    its_service->instance_);
            if (found_instance != found_service->second.end()) {
                VSOMEIP_WARNING << "Multiple configurations for service ["
                        << std::hex << its_service->service_ << "."
                        << its_service->instance_ << "]";
                is_loaded = false;
            }
        }

        if (is_loaded) {
            services_[its_service->service_][its_service->instance_] =
                    its_service;
            if (use_magic_cookies) {
                magic_cookies_[its_service->unicast_address_].insert(its_service->reliable_);
            }

            if (its_service->unicast_address_ == default_unicast_) {
                // local services
                if(its_service->reliable_ != ILLEGAL_PORT) {
                    services_by_ip_port_[unicast_.to_string()]
                                        [its_service->reliable_]
                                        [its_service->service_] = its_service;
                }
                if (its_service->unreliable_ != ILLEGAL_PORT) {
                    services_by_ip_port_[unicast_.to_string()]
                                        [its_service->unreliable_]
                                        [its_service->service_] = its_service;
                    // This is necessary as all udp server endpoints listen on
                    // INADDR_ANY instead of a specific address
                    services_by_ip_port_[boost::asio::ip::address_v4::any().to_string()]
                                        [its_service->unreliable_]
                                        [its_service->service_] = its_service;
                    services_by_ip_port_[boost::asio::ip::address_v6::any().to_string()]
                                        [its_service->unreliable_]
                                        [its_service->service_] = its_service;
                }
            } else {
                // remote services
                if (its_service->reliable_ != ILLEGAL_PORT) {
                    services_by_ip_port_[its_service->unicast_address_]
                                        [its_service->reliable_]
                                        [its_service->service_] = its_service;
                }
                if (its_service->unreliable_ != ILLEGAL_PORT) {
                    services_by_ip_port_[its_service->unicast_address_]
                                        [its_service->unreliable_]
                                        [its_service->service_] = its_service;
                }
            }
        }
    } catch (...) {
        // Intentionally left empty
    }
}

void configuration_impl::load_event(
        std::shared_ptr<service> &_service,
        const boost::property_tree::ptree &_tree) {
    for (auto i = _tree.begin(); i != _tree.end(); ++i) {
        event_t its_event_id(0);
        bool its_is_field(false);
        reliability_type_e its_reliability(reliability_type_e::RT_UNKNOWN);
        uint32_t its_cycle_value;
        std::chrono::milliseconds its_cycle(std::chrono::milliseconds::zero());
        bool its_change_resets_cycle(false);
        bool its_update_on_change(true);

        for (auto j = i->second.begin(); j != i->second.end(); ++j) {
            std::string its_key(j->first);
            std::string its_value(j->second.data());
            if (its_key == "event") {
                std::stringstream its_converter;
                if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
                    its_converter << std::hex << its_value;
                } else {
                    its_converter << std::dec << its_value;
                }
                its_converter >> its_event_id;
            } else if (its_key == "is_field") {
                its_is_field = (its_value == "true");
            } else if (its_key == "is_reliable") {
                if (its_value == "true")
                    its_reliability = reliability_type_e::RT_RELIABLE;
                else
                    its_reliability = reliability_type_e::RT_UNRELIABLE;
            } else if (its_key == "cycle") {
                std::stringstream its_converter;
                its_converter << std::dec << its_value;
                its_converter >> its_cycle_value;
                its_cycle = std::chrono::milliseconds(its_cycle_value);
            } else if (its_key == "change_resets_cycle") {
                its_change_resets_cycle = (its_value == "true");
            } else if (its_key == "update_on_change") {
                its_update_on_change = (its_value == "true");
            }
        }

        if (its_event_id > 0) {
            auto found_event = _service->events_.find(its_event_id);
            if (found_event != _service->events_.end()) {
                VSOMEIP_INFO << "Multiple configurations for event ["
                        << std::hex << _service->service_ << "."
                        << _service->instance_ << "."
                        << its_event_id << "].";
            } else {
                // If event reliability type was not configured,
                if (its_reliability == reliability_type_e::RT_UNKNOWN) {
                    if (_service->unreliable_ != ILLEGAL_PORT) {
                        its_reliability = reliability_type_e::RT_UNRELIABLE;
                    } else if (_service->reliable_ != ILLEGAL_PORT) {
                        its_reliability = reliability_type_e::RT_RELIABLE;
                    }
                    VSOMEIP_WARNING << "Reliability type for event ["
                        << std::hex << _service->service_ << "."
                        << _service->instance_ << "."
                        << its_event_id << "] was not configured Using : "
                        << ((its_reliability == reliability_type_e::RT_RELIABLE)
                                ? "RT_RELIABLE" : "RT_UNRELIABLE");
                }

                auto its_event = std::make_shared<event>(
                        its_event_id, its_is_field, its_reliability,
                        its_cycle, its_change_resets_cycle,
                        its_update_on_change);
                _service->events_[its_event_id] = its_event;
            }
        }
    }
}

void configuration_impl::load_eventgroup(
        std::shared_ptr<service> &_service,
        const boost::property_tree::ptree &_tree) {
    for (auto i = _tree.begin(); i != _tree.end(); ++i) {
        auto its_eventgroup =
                std::make_shared<eventgroup>();
        for (auto j = i->second.begin(); j != i->second.end(); ++j) {
            std::stringstream its_converter;
            std::string its_key(j->first);
            std::string its_value(j->second.data());
            if (its_key == "eventgroup") {
                if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
                    its_converter << std::hex << its_value;
                } else {
                    its_converter << std::dec << its_value;
                }
                its_converter >> its_eventgroup->id_;
            } else if (its_key == "is_multicast") {
                std::string its_value(j->second.data());
                if (its_value == "true") {
                    its_eventgroup->multicast_address_ = _service->multicast_address_;
                    its_eventgroup->multicast_port_ = _service->multicast_port_;
                }
            } else if (its_key == "multicast") {
                try {
                    std::string its_value = j->second.get_child("address").data();
                    its_eventgroup->multicast_address_ = its_value;
                    its_value = j->second.get_child("port").data();
                    its_converter << its_value;
                    its_converter >> its_eventgroup->multicast_port_;
                } catch (...) {
                }
            } else if (its_key == "threshold") {
                int its_threshold(0);
                std::stringstream its_converter;
                its_converter << std::dec << its_value;
                its_converter >> std::dec >> its_threshold;
                its_eventgroup->threshold_ =
                        (its_threshold > std::numeric_limits<std::uint8_t>::max()) ?
                                std::numeric_limits<std::uint8_t>::max() :
                                static_cast<uint8_t>(its_threshold);
            } else if (its_key == "events") {
                for (auto k = j->second.begin(); k != j->second.end(); ++k) {
                    std::stringstream its_converter;
                    std::string its_value(k->second.data());
                    event_t its_event_id(0);
                    if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
                        its_converter << std::hex << its_value;
                    } else {
                        its_converter << std::dec << its_value;
                    }
                    its_converter >> its_event_id;
                    if (0 < its_event_id) {
                        std::shared_ptr<event> its_event(nullptr);
                        auto find_event = _service->events_.find(its_event_id);
                        if (find_event != _service->events_.end()) {
                            its_event = find_event->second;
                        } else {
                            its_event = std::make_shared<event>(its_event_id,
                                            false, reliability_type_e::RT_UNRELIABLE,
                                            std::chrono::milliseconds::zero(),
                                            false, true);
                        }
                        if (its_event) {
                            its_event->groups_.push_back(its_eventgroup);
                            its_eventgroup->events_.insert(its_event);
                            _service->events_[its_event_id] = its_event;
                        }
                    }
                }
            }
        }

        if (its_eventgroup->id_ > 0) {
            _service->eventgroups_[its_eventgroup->id_] = its_eventgroup;
        }
    }
}

void configuration_impl::load_internal_services(const configuration_element &_element) {
    try {
        auto optional = _element.tree_.get_child_optional("internal_services");
        if (!optional) {
            return;
        }
        auto its_internal_services = _element.tree_.get_child("internal_services");
        for (auto found_range = its_internal_services.begin();
                found_range != its_internal_services.end(); ++found_range) {
            service_instance_range range;
            range.first_service_ = 0x0;
            range.last_service_ = 0x0;
            range.first_instance_ = 0x0;
            range.last_instance_ = 0xffff;
            for (auto i = found_range->second.begin();
                    i != found_range->second.end(); ++i) {
                if (i->first == "first") {
                    if (i->second.size() == 0) {
                        std::stringstream its_converter;
                        std::string value = i->second.data();
                        its_converter << std::hex << value;
                        its_converter >> range.first_service_;
                    }
                    for (auto n = i->second.begin();
                            n != i->second.end(); ++n) {
                        if (n->first == "service") {
                            std::stringstream its_converter;
                            std::string value = n->second.data();
                            its_converter << std::hex << value;
                            its_converter >> range.first_service_;
                        } else if (n->first == "instance") {
                            std::stringstream its_converter;
                            std::string value = n->second.data();
                            its_converter << std::hex << value;
                            its_converter >> range.first_instance_;
                        }
                    }
                } else if (i->first == "last") {
                    if (i->second.size() == 0) {
                        std::stringstream its_converter;
                        std::string value = i->second.data();
                        its_converter << std::hex << value;
                        its_converter >> range.last_service_;
                    }
                    for (auto n = i->second.begin();
                            n != i->second.end(); ++n) {
                        if (n->first == "service") {
                            std::stringstream its_converter;
                            std::string value = n->second.data();
                            its_converter << std::hex << value;
                            its_converter >> range.last_service_;
                        } else if (n->first == "instance") {
                            std::stringstream its_converter;
                            std::string value = n->second.data();
                            its_converter << std::hex << value;
                            its_converter >> range.last_instance_;
                        }
                    }
                }
            }
            if (range.last_service_ >= range.first_service_) {
                if (range.last_instance_ >= range.first_instance_) {
                    internal_service_ranges_.push_back(range);
                }
            }
        }
    } catch (...) {
        VSOMEIP_ERROR << "Error parsing internal service range configuration!";
    }
}

void configuration_impl::load_clients(const configuration_element &_element) {
    try {
        auto its_clients = _element.tree_.get_child("clients");
        for (auto i = its_clients.begin(); i != its_clients.end(); ++i)
            load_client(i->second);
    } catch (...) {
        // intentionally left empty!
    }
}

void configuration_impl::load_client(const boost::property_tree::ptree &_tree) {
    try {
        auto its_client = std::make_shared<client>();
        its_client->remote_ports_[true]  = std::make_pair(ILLEGAL_PORT, ILLEGAL_PORT);
        its_client->remote_ports_[false] = std::make_pair(ILLEGAL_PORT, ILLEGAL_PORT);
        its_client->client_ports_[true]  = std::make_pair(ILLEGAL_PORT, ILLEGAL_PORT);
        its_client->client_ports_[false] = std::make_pair(ILLEGAL_PORT, ILLEGAL_PORT);
        its_client->last_used_specific_client_port_[true]  = ILLEGAL_PORT;
        its_client->last_used_specific_client_port_[false] = ILLEGAL_PORT;
        its_client->last_used_client_port_[true]  = ILLEGAL_PORT;
        its_client->last_used_client_port_[false] = ILLEGAL_PORT;

        for (auto i = _tree.begin(); i != _tree.end(); ++i) {
            std::string its_key(i->first);
            std::string its_value(i->second.data());
            std::stringstream its_converter;

            if (its_key == "reliable_remote_ports") {
                its_client->remote_ports_[true] = load_client_port_range(i->second);
            } else if (its_key == "unreliable_remote_ports") {
                its_client->remote_ports_[false] = load_client_port_range(i->second);
            } else if (its_key == "reliable_client_ports") {
                its_client->client_ports_[true] = load_client_port_range(i->second);
            } else if (its_key == "unreliable_client_ports") {
                its_client->client_ports_[false] = load_client_port_range(i->second);
            } else if (its_key == "reliable") {
                its_client->ports_[true] = load_client_ports(i->second);
            } else if (its_key == "unreliable") {
                its_client->ports_[false] = load_client_ports(i->second);
            } else {
                // Trim "its_value"
                if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
                    its_converter << std::hex << its_value;
                } else {
                    its_converter << std::dec << its_value;
                }

                if (its_key == "service") {
                    its_converter >> its_client->service_;
                } else if (its_key == "instance") {
                    its_converter >> its_client->instance_;
                }
            }
        }
        clients_.push_back(its_client);
    } catch (...) {
    }
}

std::set<uint16_t> configuration_impl::load_client_ports(
        const boost::property_tree::ptree &_tree) {
    std::set<uint16_t> its_ports;
    for (auto i = _tree.begin(); i != _tree.end(); ++i) {
        std::string its_value(i->second.data());
        uint16_t its_port_value;

        std::stringstream its_converter;
        if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
            its_converter << std::hex << its_value;
        } else {
            its_converter << std::dec << its_value;
        }
        its_converter >> its_port_value;
        its_ports.insert(its_port_value);
    }
    return its_ports;
}

std::pair<uint16_t,uint16_t> configuration_impl::load_client_port_range(
        const boost::property_tree::ptree &_tree) {
    std::pair<uint16_t,uint16_t> its_port_range;
    uint16_t its_first_port = ILLEGAL_PORT;
    uint16_t its_last_port = ILLEGAL_PORT;

    for (auto i = _tree.begin(); i != _tree.end(); ++i) {
        std::string its_key(i->first);
        std::string its_value(i->second.data());
        std::stringstream its_converter;

        if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
            its_converter << std::hex << its_value;
        } else {
            its_converter << std::dec << its_value;
        }

        if (its_key == "first") {
            its_converter >> its_first_port;
        } else if (its_key == "last") {
            its_converter >> its_last_port;
        }
    }

    if (its_last_port < its_first_port) {
        VSOMEIP_WARNING << "Port range invalid: first: " << std::dec << its_first_port << " last: " << its_last_port;
        its_port_range = std::make_pair(ILLEGAL_PORT, ILLEGAL_PORT);
    } else {
        its_port_range = std::make_pair(its_first_port, its_last_port);
    }

    return its_port_range;
}

void configuration_impl::load_watchdog(const configuration_element &_element) {
    try {
        auto its_service_discovery = _element.tree_.get_child("watchdog");
        for (auto i = its_service_discovery.begin();
                i != its_service_discovery.end(); ++i) {
            std::string its_key(i->first);
            std::string its_value(i->second.data());
            std::stringstream its_converter;
            if (its_key == "enable") {
                if (is_configured_[ET_WATCHDOG_ENABLE]) {
                    VSOMEIP_WARNING << "Multiple definitions of watchdog.enable."
                            " Ignoring definition from " << _element.name_;
                } else {
                    watchdog_->is_enabeled_ = (its_value == "true");
                    is_configured_[ET_WATCHDOG_ENABLE] = true;
                }
            } else if (its_key == "timeout") {
                if (is_configured_[ET_WATCHDOG_TIMEOUT]) {
                    VSOMEIP_WARNING << "Multiple definitions of watchdog.timeout."
                            " Ignoring definition from " << _element.name_;
                } else {
                    its_converter << std::dec << its_value;
                    its_converter >> watchdog_->timeout_in_ms_;
                    is_configured_[ET_WATCHDOG_TIMEOUT] = true;
                }
            } else if (its_key == "allowed_missing_pongs") {
                if (is_configured_[ET_WATCHDOG_ALLOWED_MISSING_PONGS]) {
                    VSOMEIP_WARNING << "Multiple definitions of watchdog.allowed_missing_pongs."
                            " Ignoring definition from " << _element.name_;
                } else {
                    its_converter << std::dec << its_value;
                    its_converter >> watchdog_->missing_pongs_allowed_;
                    is_configured_[ET_WATCHDOG_ALLOWED_MISSING_PONGS] = true;
                }
            }
        }
    } catch (...) {
    }
}

void configuration_impl::load_payload_sizes(const configuration_element &_element) {
    const std::string payload_sizes("payload-sizes");
    const std::string max_local_payload_size("max-payload-size-local");
    const std::string buffer_shrink_threshold("buffer-shrink-threshold");
    const std::string max_reliable_payload_size("max-payload-size-reliable");
    const std::string max_unreliable_payload_size("max-payload-size-unreliable");
    try {
        for (const auto& s : { max_local_payload_size,
                max_reliable_payload_size, max_unreliable_payload_size }) {
            if (_element.tree_.get_child_optional(s)) {
                const std::string size_str(_element.tree_.get_child(s).data());
                try {
                    // add 16 Byte for the SOME/IP header
                    const auto its_size = static_cast<std::uint32_t>(
                            std::stoul(size_str.c_str(), NULL, 10) + 16);
                    if (s == max_local_payload_size) {
                        max_local_message_size_ = its_size;
                    } else if (s == max_reliable_payload_size) {
                        max_reliable_message_size_ = its_size;
                    } else if (s == max_unreliable_payload_size) {
                        max_unreliable_message_size_ = its_size;
                    }
                } catch (const std::exception &e) {
                    VSOMEIP_ERROR<< __func__ << ": " << s << " " << e.what();
                }
            }
        }

        if (_element.tree_.get_child_optional(buffer_shrink_threshold)) {
            auto bst = _element.tree_.get_child(buffer_shrink_threshold);
            std::string s(bst.data());
            try {
                buffer_shrink_threshold_ = static_cast<std::uint32_t>(
                        std::stoul(s.c_str(), NULL, 10));
            } catch (const std::exception &e) {
                VSOMEIP_ERROR<< __func__ << ": " << buffer_shrink_threshold
                << " " << e.what();
            }
        }
        if (_element.tree_.get_child_optional(payload_sizes)) {
            const std::string unicast("unicast");
            const std::string ports("ports");
            const std::string port("port");
            const std::string max_payload_size("max-payload-size");
            auto its_ps = _element.tree_.get_child(payload_sizes);
            for (auto i = its_ps.begin(); i != its_ps.end(); ++i) {
                if (!i->second.get_child_optional(unicast)
                        || !i->second.get_child_optional(ports)) {
                    continue;
                }
                std::string its_unicast(i->second.get_child(unicast).data());
                for (auto j = i->second.get_child(ports).begin();
                        j != i->second.get_child(ports).end(); ++j) {

                    if (!j->second.get_child_optional(port)
                            || !j->second.get_child_optional(max_payload_size)) {
                        continue;
                    }

                    std::uint16_t its_port = ILLEGAL_PORT;
                    std::uint32_t its_message_size = 0;

                    try {
                        std::string p(j->second.get_child(port).data());
                        its_port = static_cast<std::uint16_t>(std::stoul(p.c_str(),
                                NULL, 10));
                        std::string s(j->second.get_child(max_payload_size).data());
                        // add 16 Byte for the SOME/IP header
                        its_message_size = static_cast<std::uint32_t>(
                                std::stoul(s.c_str(), NULL, 10) + 16);
                    } catch (const std::exception &e) {
                        VSOMEIP_ERROR << __func__ << ":" << e.what();
                    }

                    if (its_port == ILLEGAL_PORT || its_message_size == 0) {
                        continue;
                    }
                    if (max_configured_message_size_ < its_message_size) {
                        max_configured_message_size_ = its_message_size;
                    }

                    message_sizes_[its_unicast][its_port] = its_message_size;
                }
            }
            if (max_local_message_size_ != 0
                    && max_configured_message_size_ != 0
                    && max_configured_message_size_ > max_local_message_size_) {
                VSOMEIP_WARNING << max_local_payload_size
                        << " is configured smaller than the biggest payloadsize"
                        << " for external communication. "
                        << max_local_payload_size << " will be increased to "
                        << max_configured_message_size_ - 16 << " to ensure "
                        << "local message distribution.";
                max_local_message_size_ = max_configured_message_size_;
            }
            if (max_local_message_size_ != 0
                    && max_reliable_message_size_ != 0
                    && max_reliable_message_size_ > max_local_message_size_) {
                VSOMEIP_WARNING << max_local_payload_size << " ("
                        << max_local_message_size_ - 16 << ") is configured"
                        << " smaller than " << max_reliable_payload_size << " ("
                        << max_reliable_message_size_ - 16 << "). "
                        << max_local_payload_size << " will be increased to "
                        << max_reliable_message_size_ - 16 << " to ensure "
                        << "local message distribution.";
                max_local_message_size_ = max_reliable_message_size_;
            }
            if (max_local_message_size_ != 0
                    && max_unreliable_message_size_ != 0
                    && max_unreliable_message_size_ > max_local_message_size_) {
                VSOMEIP_WARNING << max_local_payload_size << " ("
                        << max_local_message_size_ - 16 << ") is configured"
                        << " smaller than " << max_unreliable_payload_size << " ("
                        << max_unreliable_message_size_ - 16 << "). "
                        << max_local_payload_size << " will be increased to "
                        << max_unreliable_message_size_ - 16 << " to ensure "
                        << "local message distribution.";
                max_local_message_size_ = max_unreliable_message_size_;
            }
        }
    } catch (...) {
    }
}

void configuration_impl::load_permissions(const configuration_element &_element) {
    const std::string file_permissions("file-permissions");
    try {
        if (_element.tree_.get_child_optional(file_permissions)) {
            auto its_permissions = _element.tree_.get_child(file_permissions);
            for (auto i = its_permissions.begin(); i != its_permissions.end();
                    ++i) {
                std::string its_key(i->first);
                std::stringstream its_converter;
                if (its_key == "permissions-uds") {
                    std::string its_value(i->second.data());
                    its_converter << std::oct << its_value;
                    its_converter >> permissions_uds_;

                }
            }
        }
    } catch (...) {
    }
}

void configuration_impl::load_security(const configuration_element &_element) {

    try {
        auto its_security = _element.tree_.get_child_optional("security");
        if (its_security) {
            is_security_enabled_ = true;
            is_security_external_ = its_security->empty();

            auto its_audit_mode = its_security->get_child_optional("check_credentials");
            if (its_audit_mode) {
                if (is_configured_[ET_SECURITY_AUDIT_MODE]) {
                    VSOMEIP_WARNING << "Multiple definitions for security audit mode ("
                            << "(check_credentials). Ignoring definition from "
                            << _element.name_;
                } else {
                    is_security_audit_ = (its_audit_mode->data() != "true");
                    is_configured_[ET_SECURITY_AUDIT_MODE] = true;
                }
            }

            auto its_remote_access = its_security->get_child_optional("allow_remote_clients");
            if (its_remote_access) {
                if (is_configured_[ET_SECURITY_REMOTE_ACCESS]) {
                    VSOMEIP_WARNING << "Multiple definitions for security audit mode ("
                            << "(check_credentials). Ignoring definition from "
                            << _element.name_;
                } else {
                    is_remote_access_allowed_ = (its_remote_access->data() == "true");
                    is_configured_[ET_SECURITY_REMOTE_ACCESS] = true;
                }
            }
        }

    } catch (...) {
    }

#ifndef VSOMEIP_DISABLE_SECURITY
    if (!is_security_external())
        policy_manager_->load(_element);
#endif // !VSOMEIP_DISABLE_SECURITY
}


void configuration_impl::load_selective_broadcasts_support(const configuration_element &_element) {
    try {
        auto its_service_discovery = _element.tree_.get_child("supports_selective_broadcasts");
        for (auto i = its_service_discovery.begin();
                i != its_service_discovery.end(); ++i) {
            std::string its_value(i->second.data());
            supported_selective_addresses.insert(its_value);
        }
    } catch (...) {
    }
}


void
configuration_impl::load_partitions(const configuration_element &_element) {

    try {
        auto its_partitions = _element.tree_.get_child("partitions");
        for (auto i = its_partitions.begin(); i != its_partitions.end(); ++i) {
            load_partition(i->second);
        }
    } catch (...) {
    }
}

void
configuration_impl::load_partition(const boost::property_tree::ptree &_tree) {

    static partition_id_t its_partition_id(VSOMEIP_DEFAULT_PARTITION_ID);

    try {

        std::stringstream its_converter;
        std::map<service_t, std::set<instance_t> > its_partition_members;

        for (auto i = _tree.begin(); i != _tree.end(); ++i) {
            service_t its_service(0x0);
            instance_t its_instance(0x0);
            std::string its_service_s, its_instance_s;

            for (auto j = i->second.begin(); j != i->second.end(); ++j) {
                std::string its_key(j->first);
                std::string its_data(j->second.data());

                its_converter.str("");
                its_converter.clear();

                if (its_data.find("0x") != std::string::npos)
                    its_converter << std::hex;
                else
                    its_converter << std::dec;
                its_converter << its_data;

                if (its_key == "service") {
                    its_converter >> its_service;
                    its_service_s = its_data;
                } else if (its_key == "instance") {
                    its_converter >> its_instance;
                    its_instance_s = its_data;
                }
            }

            if (its_service > 0 && its_instance > 0)
                its_partition_members[its_service].insert(its_instance);
            else
                VSOMEIP_ERROR << "P: <" << its_service_s << "."
                    << its_instance_s << "> is no valid service instance.";

        }

        if (!its_partition_members.empty()) {
            std::lock_guard<std::mutex> its_lock(partitions_mutex_);
            its_partition_id++;

            std::stringstream its_log;
            its_log << "P"
                    << std::dec << static_cast<int>(its_partition_id)
                    << " [";

            for (const auto &p : its_partition_members) {
                for (const auto &m : p.second) {
                    partitions_[p.first][m] = its_partition_id;
                    its_log << "<"
                            << std::setfill('0') << std::hex
                            << std::setw(4) << p.first << "."
                            << std::setw(4) << m
                            << ">";
                }
            }

            its_log << "]";
            VSOMEIP_INFO << its_log.str();
        }
    } catch (...) {
    }
}

///////////////////////////////////////////////////////////////////////////////
// Internal helper
///////////////////////////////////////////////////////////////////////////////
void configuration_impl::set_magic_cookies_unicast_address() {
    // get services with static routing that have magic cookies enabled
    std::map<std::string, std::set<uint16_t> > its_magic_cookies_ = magic_cookies_;
    its_magic_cookies_.erase(default_unicast_);

    //set unicast address of host for all services without static routing
    its_magic_cookies_[get_unicast_address().to_string()].insert(
            magic_cookies_[default_unicast_].begin(),
            magic_cookies_[default_unicast_].end());
    magic_cookies_.clear();
    magic_cookies_ = its_magic_cookies_;
}

bool configuration_impl::is_internal_service(service_t _service,
        instance_t _instance) const {

    for (auto its_range : internal_service_ranges_) {
        if (_service >= its_range.first_service_ &&
                _service <= its_range.last_service_ &&
                _instance >= its_range.first_instance_ &&
                _instance <= its_range.last_instance_) {
            return true;
        }
    }
    return false;
}

bool configuration_impl::is_in_port_range(uint16_t _port,
      std::pair<uint16_t, uint16_t> _port_range) const {

    if (_port >= _port_range.first &&
            _port <= _port_range.second ) {
        return true;
    }
    return false;
}

///////////////////////////////////////////////////////////////////////////////
// Public interface
///////////////////////////////////////////////////////////////////////////////
const std::string &configuration_impl::get_network() const {
    return network_;
}

const boost::asio::ip::address & configuration_impl::get_unicast_address() const {
    return unicast_;
}

const boost::asio::ip::address& configuration_impl::get_netmask() const {
    return netmask_;
}

unsigned short configuration_impl::get_prefix() const {
    return prefix_;
}

const std::string &configuration_impl::get_device() const {
    return device_;
}

diagnosis_t configuration_impl::get_diagnosis_address() const {
    return diagnosis_;
}

diagnosis_t configuration_impl::get_diagnosis_mask() const {
    return diagnosis_mask_;
}

bool configuration_impl::is_v4() const {
    return unicast_.is_v4();
}

bool configuration_impl::is_v6() const {
    return unicast_.is_v6();
}

bool configuration_impl::has_console_log() const {
    return has_console_log_;
}

bool configuration_impl::has_file_log() const {
    return has_file_log_;
}

bool configuration_impl::has_dlt_log() const {
    return has_dlt_log_;
}

const std::string & configuration_impl::get_logfile() const {
    return logfile_;
}

vsomeip_v3::logger::level_e configuration_impl::get_loglevel() const {
    std::unique_lock<std::mutex> its_lock(mutex_loglevel_);
    return loglevel_;
}

std::string configuration_impl::get_unicast_address(service_t _service,
        instance_t _instance) const {
    std::string its_unicast_address("");
    auto its_service = find_service(_service, _instance);
    if (its_service) {
        its_unicast_address = its_service->unicast_address_;
    }

    if (its_unicast_address == default_unicast_ || its_unicast_address == "") {
            its_unicast_address = get_unicast_address().to_string();
    }
    return its_unicast_address;
}

uint16_t configuration_impl::get_reliable_port(service_t _service,
        instance_t _instance) const {
    std::lock_guard<std::mutex> its_lock(services_mutex_);
    uint16_t its_reliable(ILLEGAL_PORT);
    auto its_service = find_service_unlocked(_service, _instance);
    if (its_service)
        its_reliable = its_service->reliable_;

    return its_reliable;
}

uint16_t configuration_impl::get_unreliable_port(service_t _service,
        instance_t _instance) const {
    std::lock_guard<std::mutex> its_lock(services_mutex_);
    uint16_t its_unreliable = ILLEGAL_PORT;
     auto its_service = find_service_unlocked(_service, _instance);
    if (its_service)
        its_unreliable = its_service->unreliable_;

    return its_unreliable;
}

void configuration_impl::get_configured_timing_requests(
        service_t _service, const std::string &_ip_target,
        std::uint16_t _port_target, method_t _method,
        std::chrono::nanoseconds *_debounce_time,
        std::chrono::nanoseconds *_max_retention_time) const {

    if (_debounce_time == nullptr || _max_retention_time == nullptr) {
        return;
    }

    auto its_service = find_service(_service, _ip_target, _port_target);
    if (its_service) {
        auto find_method = its_service->debounce_times_requests_.find(_method);
        if (find_method != its_service->debounce_times_requests_.end()) {
            *_debounce_time = find_method->second[0];
            *_max_retention_time = find_method->second[1];
            return;
        }
    }

    *_debounce_time = npdu_default_debounce_requ_;
    *_max_retention_time = npdu_default_max_retention_requ_;
}

void configuration_impl::get_configured_timing_responses(
        service_t _service, const std::string &_ip_service,
        std::uint16_t _port_service, method_t _method,
        std::chrono::nanoseconds *_debounce_time,
        std::chrono::nanoseconds *_max_retention_time) const {
    if (_debounce_time == nullptr || _max_retention_time == nullptr) {
        return;
    }

    auto its_service = find_service(_service, _ip_service, _port_service);
    if (its_service) {
        auto find_method = its_service->debounce_times_responses_.find(_method);
        if (find_method != its_service->debounce_times_responses_.end()) {
            *_debounce_time = find_method->second[0];
            *_max_retention_time = find_method->second[1];
            return;
        }
    }

    *_debounce_time = npdu_default_debounce_resp_;
    *_max_retention_time  = npdu_default_max_retention_resp_;
}

bool configuration_impl::is_someip(service_t _service,
        instance_t _instance) const {
    auto its_service = find_service(_service, _instance);
    if (its_service)
        return (its_service->protocol_ == "someip");
    return true; // we need to explicitely configure a service to
                 // be something else than SOME/IP
}

bool configuration_impl::get_client_port(
        service_t _service, instance_t _instance,
        uint16_t _remote_port, bool _reliable,
        std::map<bool, std::set<uint16_t> > &_used_client_ports,
        uint16_t &_client_port) const {
    bool is_configured(false);
    _client_port = ILLEGAL_PORT;

    uint16_t its_specific_port(ILLEGAL_PORT);
    if (find_specific_port(its_specific_port, _service, _instance, _reliable, _used_client_ports)) {
        is_configured = true;
        if (its_specific_port != ILLEGAL_PORT) {
            _client_port = its_specific_port;
            return true;
        }
    }

    // No specific port configuration found, use generic configuration
    uint16_t its_port(ILLEGAL_PORT);
    if (find_port(its_port, _remote_port, _reliable, _used_client_ports)) {
        is_configured = true;
        if (its_port != ILLEGAL_PORT) {
            _client_port = its_port;
            return true;
        }
    }

    if (!is_configured) {
        // Neither specific not generic configurarion available,
        // use dynamic port configuration!
        _client_port = 0;
        return true;
    }

    // Configured ports do exist, but they are all in use
    VSOMEIP_ERROR << "Cannot find free client port for communication to service ["
                  << std::hex << std::setw(4) << std::setfill('0') << _service << "."
                  << std::hex << std::setw(4) << std::setfill('0') << _instance << "."
                  << std::dec << _remote_port << "."
                  << std::boolalpha <<_reliable << "]";

    return false;
}

bool configuration_impl::has_enabled_magic_cookies(const std::string &_address,
        uint16_t _port) const {
    bool has_enabled(false);
    auto find_address = magic_cookies_.find(_address);
    if (find_address != magic_cookies_.end()) {
        auto find_port = find_address->second.find(_port);
        if (find_port != find_address->second.end()) {
            has_enabled = true;
        }
    }
    return has_enabled;
}

bool configuration_impl::is_routing_enabled() const {
    return routing_.is_enabled_;
}

const std::string &
configuration_impl::get_routing_host_name() const {

    return routing_.host_.name_;
}

const boost::asio::ip::address &
configuration_impl::get_routing_host_address() const {

    return routing_.host_.unicast_;
}

port_t
configuration_impl::get_routing_host_port() const {

    return routing_.host_.port_;
}

const boost::asio::ip::address &
configuration_impl::get_routing_guest_address() const {

    return routing_.guests_.unicast_;
}

std::set<std::pair<port_t, port_t> >
configuration_impl::get_routing_guest_ports(uid_t _uid, gid_t _gid) const {

    auto found = routing_.guests_.ports_.find({ _uid, _gid });
    if (found != routing_.guests_.ports_.end())
            return found->second;

    found = routing_.guests_.ports_.find({ _uid, ANY_GID });
    if (found != routing_.guests_.ports_.end())
            return found->second;

    found = routing_.guests_.ports_.find({ ANY_UID, _gid });
    if (found != routing_.guests_.ports_.end())
            return found->second;

    found = routing_.guests_.ports_.find({ ANY_UID, ANY_GID });
    if (found != routing_.guests_.ports_.end())
            return found->second;

    return std::set<std::pair<port_t, port_t> >();
}

bool
configuration_impl::is_local_routing() const {

    bool is_local(true);
    try {
        is_local = routing_.host_.unicast_.is_unspecified() ||
                routing_.host_.unicast_.is_multicast();
    } catch (...) {
    }

    return is_local;
}

client_t configuration_impl::get_id(const std::string &_name) const {
    client_t its_client(VSOMEIP_CLIENT_UNSET);

    auto found_application = applications_.find(_name);
    if (found_application != applications_.end()) {
        its_client = found_application->second.client_;
    }

    return its_client;
}

bool configuration_impl::is_configured_client_id(client_t _id) const {
    return (client_identifiers_.find(_id) != client_identifiers_.end());
}

std::size_t configuration_impl::get_request_debouncing(const std::string &_name) const {
    size_t its_request_debouncing(VSOMEIP_REQUEST_DEBOUNCE_TIME);
    auto found_application = applications_.find(_name);
    if (found_application != applications_.end()) {
        its_request_debouncing = found_application->second.request_debouncing_;
    }

    return its_request_debouncing;
}

std::size_t configuration_impl::get_io_thread_count(const std::string &_name) const {
    std::size_t its_io_thread_count = VSOMEIP_DEFAULT_IO_THREAD_COUNT;

    auto found_application = applications_.find(_name);
    if (found_application != applications_.end()) {
        its_io_thread_count = found_application->second.thread_count_;
    }

    return its_io_thread_count;
}

int configuration_impl::get_io_thread_nice_level(const std::string &_name) const {
    int its_io_thread_nice_level = VSOMEIP_DEFAULT_IO_THREAD_NICE_LEVEL;

    auto found_application = applications_.find(_name);
    if (found_application != applications_.end()) {
        its_io_thread_nice_level = found_application->second.nice_level_;
    }

    return its_io_thread_nice_level;
}

std::size_t configuration_impl::get_max_dispatchers(
        const std::string &_name) const {

    std::size_t its_max_dispatchers(VSOMEIP_MAX_DISPATCHERS);

    auto found_application = applications_.find(_name);
    if (found_application != applications_.end()) {
        its_max_dispatchers = found_application->second.max_dispatchers_;
    }

    return its_max_dispatchers;
}

std::size_t configuration_impl::get_max_dispatch_time(
        const std::string &_name) const {
    std::size_t its_max_dispatch_time = VSOMEIP_MAX_DISPATCH_TIME;

    auto found_application = applications_.find(_name);
    if (found_application != applications_.end()) {
        its_max_dispatch_time = found_application->second.max_dispatch_time_;
    }

    return its_max_dispatch_time;
}

std::size_t configuration_impl::get_max_detached_thread_wait_time(const std::string& _name) const {
    std::size_t its_max_detached_thread_wait_time = VSOMEIP_MAX_WAIT_TIME_DETACHED_THREADS;

    if (auto found_application = applications_.find(_name);
        found_application != applications_.end()) {
        its_max_detached_thread_wait_time = found_application->second.max_detach_thread_wait_time_;
    }

    return its_max_detached_thread_wait_time;
}

bool configuration_impl::has_session_handling(const std::string &_name) const {

    bool its_value(true);

    auto found_application = applications_.find(_name);
    if (found_application != applications_.end())
        its_value = found_application->second.has_session_handling_;

    return its_value;
}

std::set<std::pair<service_t, instance_t> >
configuration_impl::get_remote_services() const {
    std::lock_guard<std::mutex> its_lock(services_mutex_);
    std::set<std::pair<service_t, instance_t> > its_remote_services;
    for (const auto& i : services_) {
        for (const auto& j : i.second) {
            if (is_remote(j.second)) {
                its_remote_services.insert(std::make_pair(i.first, j.first));
            }
        }
    }
    return its_remote_services;
}

bool configuration_impl::is_mandatory(const std::string &_name) const {
    std::set<std::string> its_candidates;
    for (const auto& m : mandatory_) {
        if (m.size() <= _name.size()) {
            its_candidates.insert(m);
        }
    }

    if (its_candidates.empty())
        return false;

    for (const auto& c : its_candidates) {
        if (std::equal(c.rbegin(), c.rend(), _name.rbegin())) {
            return true;
        }
    }

    return false;
}

void configuration_impl::set_mandatory(const std::string &_input) {
    if (_input.length() > 0) {
        auto found_separator = _input.find(',');
        std::string its_mandatory_file = _input.substr(0, found_separator);
        trim(its_mandatory_file);
        mandatory_.insert(its_mandatory_file);
        while (found_separator != std::string::npos) {
            auto last_separator = found_separator+1;
            found_separator = _input.find(',', last_separator);
            its_mandatory_file
                = _input.substr(last_separator, found_separator - last_separator);
            trim(its_mandatory_file);
            mandatory_.insert(its_mandatory_file);
        }
    }
}

void configuration_impl::trim(std::string &_s) {
    _s.erase(
        _s.begin(),
        std::find_if(
            _s.begin(),
            _s.end(),
            [](const auto ch) { return !std::isspace(ch); }
        )
    );

    _s.erase(
        std::find_if(
            _s.rbegin(),
            _s.rend(),
            [](const auto ch) { return !std::isspace(ch); }
        ).base(),
        _s.end()
    );
}

bool configuration_impl::is_remote(const std::shared_ptr<service>& _service) const {
    return  (_service->unicast_address_ != default_unicast_ &&
            _service->unicast_address_ != "" &&
            _service->unicast_address_ != unicast_.to_string() &&
            _service->unicast_address_ != VSOMEIP_UNICAST_ADDRESS);
}

bool configuration_impl::get_multicast(service_t _service,
            instance_t _instance, eventgroup_t _eventgroup,
            std::string &_address, uint16_t &_port) const
{
    std::shared_ptr<eventgroup> its_eventgroup
        = find_eventgroup(_service, _instance, _eventgroup);
    if (!its_eventgroup)
        return false;

    if (its_eventgroup->multicast_address_.empty())
        return false;

    _address = its_eventgroup->multicast_address_;
    _port = its_eventgroup->multicast_port_;
    return true;
}

uint8_t configuration_impl::get_threshold(service_t _service,
        instance_t _instance, eventgroup_t _eventgroup) const {
    std::shared_ptr<eventgroup> its_eventgroup
        = find_eventgroup(_service, _instance, _eventgroup);
    return (its_eventgroup ? its_eventgroup->threshold_ : 0);
}

std::shared_ptr<client> configuration_impl::find_client(service_t _service,
        instance_t _instance) const {
    std::list<std::shared_ptr<client>>::const_iterator it;

    for (it = clients_.begin(); it != clients_.end(); ++it){
        // client was configured for specific service / instance
        if ((*it)->service_ == _service
                && (*it)->instance_ == _instance) {
            return *it;
        }
    }
    return nullptr;
}

void configuration_impl::get_event_update_properties(
        service_t _service, instance_t _instance, event_t _event,
        std::chrono::milliseconds &_cycle,
        bool &_change_resets_cycle, bool &_update_on_change) const {

    auto find_service = services_.find(_service);
    if (find_service != services_.end()) {
        auto find_instance = find_service->second.find(_instance);
        if (find_instance != find_service->second.end()) {
            auto its_service = find_instance->second;
            auto find_event = its_service->events_.find(_event);
            if (find_event != its_service->events_.end()) {
                _cycle = find_event->second->cycle_;
                _change_resets_cycle = find_event->second->change_resets_cycle_;
                _update_on_change = find_event->second->update_on_change_;
                return;
            }
        }
    }

    _cycle = std::chrono::milliseconds::zero();
    _change_resets_cycle = false;
    _update_on_change = true;
}


bool configuration_impl::find_port(uint16_t &_port, uint16_t _remote, bool _reliable,
        std::map<bool, std::set<uint16_t> > &_used_client_ports) const {
    bool is_configured(false);
    std::list<std::shared_ptr<client>>::const_iterator it;

    for (it = clients_.begin(); it != clients_.end(); ++it) {
        if (_remote != ILLEGAL_PORT && is_in_port_range(_remote,
                (*it)->remote_ports_[_reliable])) {
            is_configured = true;
            uint16_t its_port(ILLEGAL_PORT);
            if ((*it)->last_used_client_port_[_reliable] != ILLEGAL_PORT &&
                    is_in_port_range(((*it)->last_used_client_port_[_reliable]),
                            (*it)->client_ports_[_reliable])) {
                its_port = ++((*it)->last_used_client_port_[_reliable]);
                ((*it)->last_used_client_port_[_reliable])++;
            } else {
                ((*it)->last_used_client_port_[_reliable])++;
                // on initial start of port search
                if ((*it)->last_used_client_port_[_reliable] == ILLEGAL_PORT) {
                    its_port = (*it)->client_ports_[_reliable].first;
                } else {
                    continue;
                }
            }
            while (its_port <= (*it)->client_ports_[_reliable].second) {
                if (_used_client_ports[_reliable].find(its_port)
                        == _used_client_ports[_reliable].end()) {
                    _port = its_port;
                    (*it)->last_used_client_port_[_reliable] = its_port;
                    return true;
                }
                its_port++;
            }
        }
    }
    // no free port was found in _used_client_ports or last_used_port
    // cannot be incremented for any client port range
    // -> reset last used port for all available client port ranges
    for (it = clients_.begin(); it != clients_.end(); ++it) {
        if (_remote != ILLEGAL_PORT && is_in_port_range(_remote,
                (*it)->remote_ports_[_reliable])) {
            (*it)->last_used_client_port_[_reliable] = ILLEGAL_PORT;
        }
    }
    // ensure that all configured client ports are checked from beginning
    for (it = clients_.begin(); it != clients_.end(); ++it) {
        if (_remote != ILLEGAL_PORT && is_in_port_range(_remote,
                (*it)->remote_ports_[_reliable])) {
            uint16_t its_port(ILLEGAL_PORT);
            its_port = (*it)->client_ports_[_reliable].first;
            while (its_port <= (*it)->client_ports_[_reliable].second) {
                if (_used_client_ports[_reliable].find(its_port)
                        == _used_client_ports[_reliable].end()) {
                    _port = its_port;
                    (*it)->last_used_client_port_[_reliable] = its_port;
                    return true;
                }
                its_port++;
            }
        }
    }
    return is_configured;
}

bool configuration_impl::find_specific_port(uint16_t &_port, service_t _service,
        instance_t _instance, bool _reliable,
        std::map<bool, std::set<uint16_t> > &_used_client_ports) const {
    bool is_configured(false);
    bool check_all(false);
    std::list<std::shared_ptr<client>>::const_iterator it;
    auto its_client = find_client(_service, _instance);

    // Check for service, instance specific port configuration
    if (its_client  && !its_client->ports_[_reliable].empty()) {
        is_configured = true;
        std::set<uint16_t>::const_iterator it;
        if (its_client->last_used_specific_client_port_[_reliable] == ILLEGAL_PORT) {
            it = its_client->ports_[_reliable].begin();
        } else {
            it = its_client->ports_[_reliable].find(
                    its_client->last_used_specific_client_port_[_reliable]);
            auto it_next = std::next(it, 1);
            if (it_next != its_client->ports_[_reliable].end()) {
                check_all = true;
                it = it_next;
            } else {
                it = its_client->ports_[_reliable].begin();
            }
        }
        while (it != its_client->ports_[_reliable].end()) {
            if (_used_client_ports[_reliable].find(*it)
                    == _used_client_ports[_reliable].end()) {
                _port = *it;
                its_client->last_used_specific_client_port_[_reliable] = *it;
                VSOMEIP_INFO << "configuration_impl:find_specific_port #1:"
                        << " service: " << std::hex << _service
                        << " instance: " << _instance
                        << " reliable: " << std::dec << _reliable
                        << " return specific port: " << (uint32_t)_port;
                return true;
            }
            ++it;
        }
        if (check_all) {
            // no free port was found
            // ensure that all configured client ports are checked from beginning
            for (auto its_port : _used_client_ports[_reliable]) {
                if (_used_client_ports[_reliable].find(its_port)
                       == _used_client_ports[_reliable].end()) {
                    _port = its_port;
                    its_client->last_used_specific_client_port_[_reliable] = its_port;
                    VSOMEIP_INFO << "configuration_impl:find_specific_port #2:"
                            << " service: " << std::hex << _service
                            << " instance: " << _instance
                            << " reliable: " << std::dec << _reliable
                            << " return specific port: " << (uint32_t)_port;
                    return true;
                }
            }
        }
        its_client->last_used_specific_client_port_[_reliable] = ILLEGAL_PORT;
    }
    return is_configured;
}

reliability_type_e
configuration_impl::get_event_reliability(service_t _service,
        instance_t _instance, event_t _event) const {
    std::lock_guard<std::mutex> its_lock(services_mutex_);
    reliability_type_e its_reliability(reliability_type_e::RT_UNKNOWN);
    auto its_service = find_service_unlocked(_service, _instance);
    if (its_service) {
        auto its_event = its_service->events_.find(_event);
        if (its_event != its_service->events_.end()) {
            its_reliability = its_event->second->reliability_;
        }
    }
    return its_reliability;
}

reliability_type_e
configuration_impl::get_service_reliability(service_t _service,
        instance_t _instance) const {
    std::lock_guard<std::mutex> its_lock(services_mutex_);
    reliability_type_e its_reliability(reliability_type_e::RT_UNKNOWN);
    auto its_service = find_service_unlocked(_service, _instance);
    if (its_service) {
        if (its_service->reliable_ != ILLEGAL_PORT) {
            if (its_service->unreliable_ != ILLEGAL_PORT) {
                its_reliability = reliability_type_e::RT_BOTH;
            } else {
                its_reliability = reliability_type_e::RT_RELIABLE;
            }
        } else {
            its_reliability = reliability_type_e::RT_UNRELIABLE;
        }
    }
    return its_reliability;
}

std::shared_ptr<service> configuration_impl::find_service(service_t _service,
        instance_t _instance) const {
    std::lock_guard<std::mutex> its_lock(services_mutex_);
    return find_service_unlocked(_service, _instance);
}

std::shared_ptr<service> configuration_impl::find_service_unlocked(service_t _service,
        instance_t _instance) const {
    std::shared_ptr<service> its_service;
    auto find_service = services_.find(_service);
    if (find_service != services_.end()) {
        auto find_instance = find_service->second.find(_instance);
        if (find_instance != find_service->second.end()) {
            its_service = find_instance->second;
        }
    }
    return its_service;
}

std::shared_ptr<service>
configuration_impl::find_service(service_t _service,
        const std::string &_address, std::uint16_t _port) const {

    std::shared_ptr<service> its_service;

    auto find_address = services_by_ip_port_.find(_address);
    if (find_address != services_by_ip_port_.end()) {
        auto find_port = find_address->second.find(_port);
        if(find_port != find_address->second.end()) {
            auto find_service = find_port->second.find(_service);
            if(find_service != find_port->second.end()) {
                its_service = find_service->second;
            }
        }
    }

    return its_service;
}

std::shared_ptr<eventgroup> configuration_impl::find_eventgroup(
        service_t _service, instance_t _instance,
        eventgroup_t _eventgroup) const {
    std::shared_ptr<eventgroup> its_eventgroup;
    auto its_service = find_service(_service, _instance);
    if (its_service) {
        auto find_eventgroup = its_service->eventgroups_.find(_eventgroup);
        if (find_eventgroup != its_service->eventgroups_.end()) {
            its_eventgroup = find_eventgroup->second;
        }
    }
    return its_eventgroup;
}

std::uint32_t configuration_impl::get_max_message_size_local() const {
    if (max_local_message_size_ == 0
            && (VSOMEIP_MAX_LOCAL_MESSAGE_SIZE == 0
                    || VSOMEIP_MAX_TCP_MESSAGE_SIZE == 0)) {
        // no limit specified in configuration file and
        // defines are set to unlimited
        return MESSAGE_SIZE_UNLIMITED;
    }

    uint32_t its_max_message_size = max_local_message_size_;
    if (VSOMEIP_MAX_TCP_MESSAGE_SIZE >= its_max_message_size) {
        its_max_message_size = VSOMEIP_MAX_TCP_MESSAGE_SIZE;
    }
    if (VSOMEIP_MAX_UDP_MESSAGE_SIZE > its_max_message_size) {
        its_max_message_size = VSOMEIP_MAX_UDP_MESSAGE_SIZE;
    }
    if (its_max_message_size < max_configured_message_size_) {
        its_max_message_size = max_configured_message_size_;
    }

    // add sizes of the the routing_manager_proxy's messages
    // to the routing_manager stub
    return std::uint32_t(its_max_message_size + protocol::SEND_COMMAND_HEADER_SIZE);
}

std::uint32_t configuration_impl::get_max_message_size_reliable(
        const std::string& _address, std::uint16_t _port) const {
    const auto its_address = message_sizes_.find(_address);
    if(its_address != message_sizes_.end()) {
        const auto its_port = its_address->second.find(_port);
        if(its_port != its_address->second.end()) {
            return its_port->second;
        }
    }
    return (max_reliable_message_size_ == 0) ?
            ((VSOMEIP_MAX_TCP_MESSAGE_SIZE == 0) ? MESSAGE_SIZE_UNLIMITED :
                    VSOMEIP_MAX_TCP_MESSAGE_SIZE) : max_reliable_message_size_;
}

std::uint32_t configuration_impl::get_max_message_size_unreliable() const {
    return (max_unreliable_message_size_ == 0) ?
            MESSAGE_SIZE_UNLIMITED :  max_unreliable_message_size_;
}

std::uint32_t configuration_impl::get_buffer_shrink_threshold() const {
    return buffer_shrink_threshold_;
}

bool configuration_impl::supports_selective_broadcasts(const boost::asio::ip::address &_address) const {
    return supported_selective_addresses.find(_address.to_string()) != supported_selective_addresses.end();
}

bool configuration_impl::log_version() const {
    return log_version_;
}

uint32_t configuration_impl::get_log_version_interval() const {
    return log_version_interval_;
}

bool configuration_impl::is_offered_remote(service_t _service, instance_t _instance) const {
    uint16_t reliable_port = get_reliable_port(_service, _instance);
    uint16_t unreliable_port = get_unreliable_port(_service, _instance);
    return (reliable_port != ILLEGAL_PORT || unreliable_port != ILLEGAL_PORT);
}

bool configuration_impl::is_local_service(service_t _service, instance_t _instance) const {
    std::shared_ptr<service> s = find_service(_service, _instance);
    if (s && !is_remote(s)) {
        return true;
    }
    if (is_internal_service(_service, _instance)) {
        return true;
    }

    return false;
}

// Service Discovery configuration
bool configuration_impl::is_sd_enabled() const {
    return is_sd_enabled_;
}

const std::string & configuration_impl::get_sd_multicast() const {
    return sd_multicast_;
}

uint16_t configuration_impl::get_sd_port() const {
    return sd_port_;
}

const std::string & configuration_impl::get_sd_protocol() const {
    return sd_protocol_;
}

uint32_t configuration_impl::get_sd_initial_delay_min() const {
    return sd_initial_delay_min_;
}

uint32_t configuration_impl::get_sd_initial_delay_max() const {
    return sd_initial_delay_max_;
}

int32_t configuration_impl::get_sd_repetitions_base_delay() const {
    return sd_repetitions_base_delay_;
}

uint8_t configuration_impl::get_sd_repetitions_max() const {
    return sd_repetitions_max_;
}

ttl_t configuration_impl::get_sd_ttl() const {
    return sd_ttl_;
}

int32_t configuration_impl::get_sd_cyclic_offer_delay() const {
    return sd_cyclic_offer_delay_;
}

int32_t configuration_impl::get_sd_request_response_delay() const {
    return sd_request_response_delay_;
}

std::uint32_t configuration_impl::get_sd_offer_debounce_time() const {
    return sd_offer_debounce_time_;
}

std::uint32_t configuration_impl::get_sd_find_debounce_time() const {
    return sd_find_debounce_time_;
}

// Trace configuration
std::shared_ptr<cfg::trace> configuration_impl::get_trace() const {
    return trace_;
}

// Watchdog config
bool configuration_impl::is_watchdog_enabled() const {
    return watchdog_->is_enabeled_;
}

uint32_t configuration_impl::get_watchdog_timeout() const {
    return watchdog_->timeout_in_ms_;
}

uint32_t configuration_impl::get_allowed_missing_pongs() const {
    return watchdog_->missing_pongs_allowed_;
}
std::uint32_t configuration_impl::get_permissions_uds() const {
    return permissions_uds_;
}

std::map<plugin_type_e, std::set<std::string>> configuration_impl::get_plugins(
            const std::string &_name) const {

    std::map<plugin_type_e, std::set<std::string>> its_plugins;

    auto found_application = applications_.find(_name);
    if (found_application != applications_.end()) {
        its_plugins = found_application->second.plugins_;
    }

    return its_plugins;
}

void configuration_impl::set_configuration_path(const std::string &_path) {
    configuration_path_ = _path;
}

std::map<std::string, std::string> configuration_impl::get_additional_data(
    const std::string &_application_name,
    const std::string &_plugin_name) {

    return plugins_additional_[_application_name][_plugin_name];
}

bool configuration_impl::is_e2e_enabled() const {
    return e2e_enabled_;
}

void configuration_impl::load_e2e(const configuration_element &_element) {
#ifdef _WIN32
        return;
#endif
    try {
        auto optional = _element.tree_.get_child_optional("e2e");
        if (!optional) {
            return;
        }
        auto found_e2e = _element.tree_.get_child("e2e");
        for (auto its_e2e = found_e2e.begin();
                its_e2e != found_e2e.end(); ++its_e2e) {
            if (its_e2e->first == "e2e_enabled") {
                if (its_e2e->second.data() == "true") {
                    e2e_enabled_ = true;
                }
            }
            if (its_e2e->first == "protected") {
                for (auto its_protected = its_e2e->second.begin();
                        its_protected != its_e2e->second.end(); ++its_protected) {
                    load_e2e_protected(its_protected->second);
                }
            }
        }
    } catch (...) {
    }
}

void configuration_impl::load_e2e_protected(const boost::property_tree::ptree &_tree) {

    std::string variant("");
    std::string profile("");
    service_t service_id(0);
    event_t event_id(0);

    e2e::custom_parameters_t custom_parameters;

    for (auto l = _tree.begin(); l != _tree.end(); ++l) {
        std::stringstream its_converter;
        if (l->first == "service_id") {
            std::string value = l->second.data();
            if (value.size() > 1 && value[0] == '0' && value[1] == 'x') {
                its_converter << std::hex << value;
            } else {
                its_converter << std::dec << value;
            }
            its_converter >> service_id;
        } else if (l->first == "event_id") {
            std::string value = l->second.data();
            if (value.size() > 1 && value[0] == '0' && value[1] == 'x') {
                its_converter << std::hex << value;
            } else {
                its_converter << std::dec << value;
            }
            its_converter >> event_id;
        } else if (l->first == "variant") {
            std::string value = l->second.data();
            its_converter << value;
            its_converter >> variant;
        } else if (l->first == "profile") {
            std::string value = l->second.data();
            its_converter << value;
            its_converter >> profile;
        } else {
            custom_parameters[l->first.data()] = l->second.data();
        }
    }
    e2e_configuration_[std::make_pair(service_id, event_id)] = std::make_shared<cfg::e2e>(
        variant,
        profile,
        service_id,
        event_id,
        std::move(custom_parameters)
    );
}

std::map<e2exf::data_identifier_t, std::shared_ptr<cfg::e2e>> configuration_impl::get_e2e_configuration() const {
    return e2e_configuration_;
}

bool configuration_impl::log_memory() const {
    return log_memory_;
}

uint32_t configuration_impl::get_log_memory_interval() const {
    return log_memory_interval_;
}

bool configuration_impl::log_status() const {
    return log_status_;
}

uint32_t configuration_impl::get_log_status_interval() const {
    return log_status_interval_;
}

void configuration_impl::load_ttl_factors(
        const boost::property_tree::ptree &_tree, ttl_map_t* _target) {
    const service_t ILLEGAL_VALUE(0xffff);
    for (const auto& i : _tree) {
        service_t its_service(ILLEGAL_VALUE);
        instance_t its_instance(ILLEGAL_VALUE);
        configuration::ttl_factor_t its_ttl_factor(0);

        for (const auto& j : i.second) {
            std::string its_key(j.first);
            std::string its_value(j.second.data());
            std::stringstream its_converter;

            if (its_key == "ttl_factor") {
                its_converter << its_value;
                its_converter >> its_ttl_factor;
            } else {
                // Trim "its_value"
                if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
                    its_converter << std::hex << its_value;
                } else {
                    its_converter << std::dec << its_value;
                }

                if (its_key == "service") {
                    its_converter >> its_service;
                } else if (its_key == "instance") {
                    its_converter >> its_instance;
                }
            }
        }
        if (its_service != ILLEGAL_VALUE
            && its_instance != ILLEGAL_VALUE
            && its_ttl_factor > 0) {
            (*_target)[its_service][its_instance] = its_ttl_factor;
        } else {
            VSOMEIP_ERROR << "Invalid ttl factor configuration";
        }
    }
}

configuration::ttl_map_t configuration_impl::get_ttl_factor_offers() const {
    return ttl_factors_offers_;
}

configuration::ttl_map_t configuration_impl::get_ttl_factor_subscribes() const {
    return ttl_factors_subscriptions_;
}

configuration::endpoint_queue_limit_t
configuration_impl::get_endpoint_queue_limit(
        const std::string& _address, std::uint16_t _port) const {
    auto found_address = endpoint_queue_limits_.find(_address);
    if (found_address != endpoint_queue_limits_.end()) {
        auto found_port = found_address->second.find(_port);
        if (found_port != found_address->second.end()) {
            return found_port->second;
        }
    }
    return endpoint_queue_limit_external_;
}

configuration::endpoint_queue_limit_t
configuration_impl::get_endpoint_queue_limit_local() const {
    return endpoint_queue_limit_local_;
}

void
configuration_impl::load_endpoint_queue_sizes(const configuration_element &_element) {
    const std::string endpoint_queue_limits("endpoint-queue-limits");
    const std::string endpoint_queue_limit_external("endpoint-queue-limit-external");
    const std::string endpoint_queue_limit_local("endpoint-queue-limit-local");

    try {
        if (_element.tree_.get_child_optional(endpoint_queue_limit_external)) {
            if (is_configured_[ET_ENDPOINT_QUEUE_LIMIT_EXTERNAL]) {
                VSOMEIP_WARNING << "Multiple definitions for "
                        << endpoint_queue_limit_external
                        << " Ignoring definition from " << _element.name_;
            } else {
                is_configured_[ET_ENDPOINT_QUEUE_LIMIT_EXTERNAL] = true;
                auto mpsl = _element.tree_.get_child(
                        endpoint_queue_limit_external);
                std::string s(mpsl.data());
                try {
                    endpoint_queue_limit_external_ =
                            static_cast<configuration::endpoint_queue_limit_t>(std::stoul(
                                    s.c_str(), NULL, 10));
                } catch (const std::exception &e) {
                    VSOMEIP_ERROR<<__func__ << ": " << endpoint_queue_limit_external
                    << " " << e.what();
                }
            }
        }
        if (_element.tree_.get_child_optional(endpoint_queue_limit_local)) {
            if (is_configured_[ET_ENDPOINT_QUEUE_LIMIT_LOCAL]) {
                VSOMEIP_WARNING << "Multiple definitions for "
                        << endpoint_queue_limit_local
                        << " Ignoring definition from " << _element.name_;
            } else {
                is_configured_[ET_ENDPOINT_QUEUE_LIMIT_LOCAL] = true;
                auto mpsl = _element.tree_.get_child(endpoint_queue_limit_local);
                std::string s(mpsl.data());
                try {
                    endpoint_queue_limit_local_=
                            static_cast<configuration::endpoint_queue_limit_t>(
                                    std::stoul(s.c_str(), NULL, 10));
                } catch (const std::exception &e) {
                    VSOMEIP_ERROR<< __func__ << ": "<< endpoint_queue_limit_local
                            << " " << e.what();
                }
            }
        }

        if (_element.tree_.get_child_optional(endpoint_queue_limits)) {
            if (is_configured_[ET_ENDPOINT_QUEUE_LIMITS]) {
                VSOMEIP_WARNING << "Multiple definitions for "
                        << endpoint_queue_limits
                        << " Ignoring definition from " << _element.name_;
            } else {
                is_configured_[ET_ENDPOINT_QUEUE_LIMITS] = true;
                const std::string unicast("unicast");
                const std::string ports("ports");
                const std::string port("port");
                const std::string queue_size_limit("queue-size-limit");

                for (const auto& i : _element.tree_.get_child(endpoint_queue_limits)) {
                    if (!i.second.get_child_optional(unicast)
                            || !i.second.get_child_optional(ports)) {
                        continue;
                    }
                    std::string its_unicast(i.second.get_child(unicast).data());
                    for (const auto& j : i.second.get_child(ports)) {

                        if (!j.second.get_child_optional(port)
                                || !j.second.get_child_optional(queue_size_limit)) {
                            continue;
                        }

                        std::uint16_t its_port = ILLEGAL_PORT;
                        std::uint32_t its_queue_size_limit = 0;

                        try {
                            std::string p(j.second.get_child(port).data());
                            its_port = static_cast<std::uint16_t>(std::stoul(p.c_str(),
                                            NULL, 10));
                            std::string s(j.second.get_child(queue_size_limit).data());
                            its_queue_size_limit = static_cast<std::uint32_t>(std::stoul(
                                            s.c_str(), NULL, 10));
                        } catch (const std::exception &e) {
                            VSOMEIP_ERROR << __func__ << ":" << e.what();
                        }

                        if (its_port == ILLEGAL_PORT || its_queue_size_limit == 0) {
                            continue;
                        }

                        endpoint_queue_limits_[its_unicast][its_port] = its_queue_size_limit;
                    }
                }
            }
        }
    } catch (...) {
    }
}

void
configuration_impl::load_debounce(const configuration_element &_element) {
    try {
        auto its_debounce = _element.tree_.get_child("debounce");
        for (auto i = its_debounce.begin(); i != its_debounce.end(); ++i) {
            load_service_debounce(i->second, debounces_);
        }
    } catch (...) {
    }
}

void
configuration_impl::load_service_debounce(
        const boost::property_tree::ptree &_tree,
        debounce_configuration_t &_debounces) {

    service_t its_service(0);
    instance_t its_instance(0);
    std::map<event_t, std::shared_ptr<debounce_filter_impl_t>> its_debounces;

    for (auto i = _tree.begin(); i != _tree.end(); ++i) {
        std::string its_key(i->first);
        std::string its_value(i->second.data());
        std::stringstream its_converter;

        if (its_key == "service") {
            if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
                its_converter << std::hex << its_value;
            } else {
                its_converter << std::dec << its_value;
            }
            its_converter >> its_service;
        } else if (its_key == "instance") {
            if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
                its_converter << std::hex << its_value;
            } else {
                its_converter << std::dec << its_value;
            }
            its_converter >> its_instance;
        } else if (its_key == "events") {
            load_events_debounce(i->second, its_debounces);
        }
    }

    // TODO: Improve error handling!
    if (its_service > 0 && its_instance > 0 && !its_debounces.empty()) {
        auto find_service = debounces_.find(its_service);
        if (find_service != debounces_.end()) {
            auto find_instance = find_service->second.find(its_instance);
            if (find_instance != find_service->second.end()) {
                VSOMEIP_ERROR << "Multiple debounce configurations for service "
                    << std::hex << std::setfill('0')
                    << std::setw(4) << its_service << "."
                    << std::setw(4) << its_instance;
                return;
            }
        }
        _debounces[its_service][its_instance] = its_debounces;
    }
}

void
configuration_impl::load_events_debounce(
        const boost::property_tree::ptree &_tree,
        std::map<event_t, std::shared_ptr<debounce_filter_impl_t> > &_debounces) {

    for (auto i = _tree.begin(); i != _tree.end(); ++i) {
        load_event_debounce(i->second, _debounces);
    }
}

void
configuration_impl::load_event_debounce(
        const boost::property_tree::ptree &_tree,
        std::map<event_t, std::shared_ptr<debounce_filter_impl_t> > &_debounces) {

    event_t its_event(0);
    auto its_debounce = std::make_shared<debounce_filter_impl_t>();

    for (auto i = _tree.begin(); i != _tree.end(); ++i) {
        std::string its_key(i->first);
        std::string its_value(i->second.data());
        std::stringstream its_converter;

        if (its_key == "event") {
            if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
                its_converter << std::hex << its_value;
            } else {
                its_converter << std::dec << its_value;
            }
            its_converter >> its_event;
        } else if (its_key == "on_change") {
            its_debounce->on_change_ = (its_value == "true");
        } else if (its_key == "on_change_resets_interval") {
            its_debounce->on_change_resets_interval_ = (its_value == "true");
        } else if (its_key == "ignore") {
            load_event_debounce_ignore(i->second, its_debounce->ignore_);
        } else if (its_key == "interval") {
           if (its_value == "never") {
               its_debounce->interval_ = -1;
           } else {
               its_converter << std::dec << its_value;
               its_converter >> its_debounce->interval_;
           }
        } else if (its_key == "send_current_value_after") {
            its_debounce->send_current_value_after_ = (its_value == "true");
        }
    }

    // TODO: Improve error handling
    if (its_event > 0) {
        auto find_event = _debounces.find(its_event);
        if (find_event == _debounces.end()) {
            _debounces[its_event] = its_debounce;
        }
    }
}

void configuration_impl::load_event_debounce_ignore(
        const boost::property_tree::ptree &_tree,
        std::map<std::size_t, byte_t> &_ignore) {
    std::size_t its_ignored;
    byte_t its_mask;
    std::stringstream its_converter;

    for (auto i = _tree.begin(); i != _tree.end(); ++i) {
        std::string its_value = i->second.data();

        its_mask = 0xff;

        if (!its_value.empty()
               && std::find_if(its_value.begin(), its_value.end(),
                      [](char _c) { return !std::isdigit(_c); })
                      == its_value.end()) {
            its_converter.str("");
            its_converter.clear();
            its_converter << std::dec << its_value;
            its_converter >> its_ignored;

        } else {
            for (auto j = i->second.begin(); j != i->second.end(); ++j) {
                std::string its_ignore_key(j->first);
                std::string its_ignore_value(j->second.data());

                if (its_ignore_key == "index") {
                    its_converter.str("");
                    its_converter.clear();
                    its_converter << std::dec << its_ignore_value;
                    its_converter >> its_ignored;
                } else if (its_ignore_key == "mask") {
                    its_converter.str("");
                    its_converter.clear();

                    int its_tmp_mask;
                    its_converter << std::hex << its_ignore_value;
                    its_converter >> its_tmp_mask;

                    its_mask = static_cast<byte_t>(its_tmp_mask);
                }
            }
        }

        _ignore[its_ignored] = its_mask;
    }
}

void
configuration_impl::load_acceptances(
        const configuration_element &_element) {

    std::string its_acceptances_key("acceptances");
    try {
        auto its_acceptances = _element.tree_.get_child_optional(its_acceptances_key);
        if (its_acceptances) {
            if (is_configured_[ET_SD_ACCEPTANCE_REQUIRED]) {
                VSOMEIP_WARNING << "Multiple definitions of " << its_acceptances_key
                        << " Ignoring definition from " << _element.name_;
                return;
            }

            for (auto i = its_acceptances->begin(); i != its_acceptances->end(); ++i) {
                load_acceptance_data(i->second);
            }

            is_configured_[ET_SD_ACCEPTANCE_REQUIRED] = true;
        }
    } catch (...) {
        // Intentionally left empty
    }
}

void
configuration_impl::load_acceptance_data(
        const boost::property_tree::ptree &_tree) {

    std::stringstream its_converter;
    try {
        std::lock_guard<std::mutex> its_lock(sd_acceptance_required_ips_mutex_);

        boost::asio::ip::address its_address;
        std::string its_path;
        std::map<bool,
            std::pair<boost::icl::interval_set<std::uint16_t>,
                boost::icl::interval_set<std::uint16_t>
            >
        > its_ports;
        bool has_optional, has_secure, is_reliable;

        for (auto i = _tree.begin(); i != _tree.end(); ++i) {

            std::string its_key(i->first);
            std::string its_value(i->second.data());

            if (its_key == "address") {
                its_address = boost::asio::ip::address::from_string(its_value);
            } else if (its_key == "path") {
                its_path = its_value;
            } else if (its_key == "reliable" || its_key == "unreliable") {

                is_reliable = (its_key == "reliable");
                has_optional = has_secure = false;

                for (const auto &p : i->second) {
                    if (p.second.size()) { // range
                        std::uint16_t its_first(0);
                        std::uint16_t its_last(0);
                        port_type_e its_type(port_type_e::PT_OPTIONAL);

                        for (const auto& range : p.second) {
                            const std::string its_key(range.first);
                            const std::string its_value(range.second.data());
                            if (its_key == "first" || its_key == "last" || its_key == "port") {
                                its_converter << std::dec << its_value;
                                std::uint16_t its_port_value(0);
                                its_converter >> its_port_value;
                                its_converter.str("");
                                its_converter.clear();
                                if (its_key == "first") {
                                    its_first = its_port_value;
                                } else if (its_key == "last") {
                                    its_last = its_port_value;
                                } else if (its_key == "port") {
                                    its_first = its_last = its_port_value;
                                }
                            } else if (its_key == "type") {
                                if (its_value == "secure") {
                                    its_type = port_type_e::PT_SECURE;
                                } else if (its_value == "optional") {
                                    its_type = port_type_e::PT_OPTIONAL;
                                } else {
                                    its_type = port_type_e::PT_UNKNOWN;
                                }
                            }
                        }
                        if (its_type != port_type_e::PT_UNKNOWN) {
                            if (its_type == port_type_e::PT_OPTIONAL) {
                                has_optional = true;
                                if (its_first != 0 && its_last != 0) {
                                    its_ports.operator [](is_reliable).first.insert(
                                            boost::icl::interval<std::uint16_t>::closed(its_first, its_last));
                                }
                            } else {
                                has_secure = true;
                                if (its_first != 0 && its_last != 0) {
                                    its_ports.operator [](is_reliable).second.insert(
                                        boost::icl::interval<std::uint16_t>::closed(its_first, its_last));
                                }
                            }
                        }
                    }
                }

                // If optional was not set, use default!
                if (!has_optional) {
                    const auto its_optional_client = boost::icl::interval<std::uint16_t>::closed(30491, 30499);
                    const auto its_optional_client_spare = boost::icl::interval<std::uint16_t>::closed(30898, 30998);
                    const auto its_optional_server = boost::icl::interval<std::uint16_t>::closed(30501, 30599);

                    its_ports.operator [](is_reliable).first.insert(its_optional_client);
                    its_ports.operator [](is_reliable).first.insert(its_optional_client_spare);
                    its_ports.operator [](is_reliable).first.insert(its_optional_server);
                }

                // If secure was not set, use default!
                if (!has_secure) {
                    const auto its_secure_client = boost::icl::interval<std::uint16_t>::closed(32491, 32499);
                    const auto its_secure_client_spare = boost::icl::interval<std::uint16_t>::closed(32898, 32998);
                    const auto its_secure_server = boost::icl::interval<std::uint16_t>::closed(32501, 32599);

                    its_ports.operator [](is_reliable).second.insert(its_secure_client);
                    its_ports.operator [](is_reliable).second.insert(its_secure_client_spare);
                    its_ports.operator [](is_reliable).second.insert(its_secure_server);
                }
            }
        }

        if (!its_address.is_unspecified()) {
            sd_acceptance_rules_[its_address] = std::make_pair(its_path, its_ports);
        }
    } catch (...) {
        // intentionally left empty
    }
}

bool configuration_impl::load_npdu_debounce_times_configuration(
        const std::shared_ptr<service>& _service,
        const boost::property_tree::ptree &_tree) {
    bool is_loaded(true);
    try {
        for (const auto& i : _tree) {
            const std::string its_key(i.first);
            if (its_key == "requests") {
                if (!load_npdu_debounce_times_for_service(_service, true, i.second)) {
                    is_loaded = false;
                }
            } else if (its_key == "responses") {
                if (!load_npdu_debounce_times_for_service(_service, false, i.second)) {
                    is_loaded = false;
                }
            }
        }
    } catch (...) {
        is_loaded = false;
    }
    return is_loaded;
}

bool configuration_impl::load_npdu_debounce_times_for_service(
        const std::shared_ptr<service>& _service, bool _is_request,
        const boost::property_tree::ptree &_tree) {
    const std::string dtime("debounce-time");
    const std::string rtime("maximum-retention-time");

    bool is_loaded(true);
    try {
        std::stringstream its_converter;
        for (const auto& i : _tree) {
            const std::string its_method_str(i.first.data());
            if (its_method_str.size()) {
                method_t its_method = 0xFFFF;
                if (its_method_str.size() > 1 && its_method_str[0] == '0'
                        && its_method_str[1] == 'x') {
                    its_converter << std::hex << its_method_str;
                } else {
                    its_converter << std::dec << its_method_str;
                }
                its_converter >> its_method;
                its_converter.str("");
                its_converter.clear();

                std::chrono::nanoseconds its_debounce_time(
                        npdu_default_debounce_requ_);
                std::chrono::nanoseconds its_retention_time(
                        npdu_default_max_retention_requ_);
                for (const auto& j : i.second) {
                    const std::string& key = j.first;
                    const std::uint64_t value = std::strtoull(
                                                        j.second.data().c_str(),
                                                        NULL, 10) * 1000000;
                    if (key == dtime) {
                        its_debounce_time = std::chrono::nanoseconds(value);
                    } else if (key == rtime) {
                        its_retention_time = std::chrono::nanoseconds(value);
                    }
                }
                if (_is_request) {
                    _service->debounce_times_requests_[its_method]
                            = {its_debounce_time, its_retention_time};
                } else {
                    _service->debounce_times_responses_[its_method]
                            = { its_debounce_time, its_retention_time};
                }
            }
        }
    } catch (...) {
        is_loaded = false;
    }
    return is_loaded;
}

void configuration_impl::load_someip_tp(
        const std::shared_ptr<service>& _service,
        const boost::property_tree::ptree &_tree) {
    try {
        for (const auto& i : _tree) {
            const std::string its_key(i.first);
            if (its_key == "client-to-service") {
                load_someip_tp_for_service(_service, i.second, true);
            } else if (its_key == "service-to-client") {
                load_someip_tp_for_service(_service, i.second, false);
            }
        }
    } catch (...) {
        // intentionally left empty
    }
}

void configuration_impl::load_someip_tp_for_service(
        const std::shared_ptr<service>& _service,
        const boost::property_tree::ptree &_tree, bool _is_request) {
    try {
        std::stringstream its_converter;
        for (const auto& method : _tree) {
            method_t its_method(0);
            uint16_t its_max_segment_length(VSOMEIP_TP_MAX_SEGMENT_LENGTH_DEFAULT);
            uint32_t its_separation_time(0);

            const std::string its_value(method.second.data());
            if (its_value.empty()) {
                for (const auto &its_data : method.second) {
                    const std::string its_value(its_data.second.data());
                    if (!its_value.empty()) {
                        if (its_data.first == "method") {
                            if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
                                its_converter << std::hex << its_value;
                            } else {
                                its_converter << std::dec << its_value;
                            }
                            its_converter >> its_method;
                        } else if (its_data.first == "max-segment-length") {
                            its_converter << std::dec << its_value;
                            its_converter >> its_max_segment_length;

                            // Segment length must be multiple of 16
                            // Ensure this by subtracting the rest
                            auto its_rest = std::uint16_t(its_max_segment_length % 16);
                            if (its_rest != 0) {
                                VSOMEIP_WARNING << "SOMEIP/TP: max-segment-length must be multiple of 16. Corrected "
                                    << std::dec << its_max_segment_length << " to "
                                    << std::dec << its_max_segment_length-its_rest;

                                its_max_segment_length = std::uint16_t(its_max_segment_length - its_rest);
                            }
                        } else if (its_data.first == "separation-time") {
                            its_converter << std::dec << its_value;
                            its_converter >> its_separation_time;
                            its_separation_time *= std::uint32_t(1000);
                        }
                    }
                    its_converter.str("");
                    its_converter.clear();
                }
            } else {
                if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
                    its_converter << std::hex << its_value;
                } else {
                    its_converter << std::dec << its_value;
                }
                its_converter >> its_method;
                its_converter.str("");
                its_converter.clear();
            }

            if (its_method != 0) {
                if (_is_request) {
                    const auto its_entry = _service->tp_client_config_.find(its_method);
                    if (its_entry == _service->tp_client_config_.end()) {
                        _service->tp_client_config_[its_method]
                            = std::make_pair(its_max_segment_length, its_separation_time);
                    } else {
                        VSOMEIP_WARNING << "SOME/IP-TP: Multiple client configurations for method ["
                                << std::hex << std::setfill('0')
                                << std::setw(4) << _service->service_ << "."
                                << std::setw(4) << _service->instance_ << "."
                                << std::setw(4) << its_method << "]:"
                                << " using (" << std::dec
                                << its_entry->second.first << ", "
                                << its_entry->second.second << ")";
                    }
                } else {
                    const auto its_entry = _service->tp_service_config_.find(its_method);
                    if (its_entry == _service->tp_service_config_.end()) {
                        _service->tp_service_config_[its_method]
                            = std::make_pair(its_max_segment_length, its_separation_time);
                    } else {
                        VSOMEIP_WARNING << "SOME/IP-TP: Multiple service configurations for method ["
                                << std::hex << std::setfill('0')
                                << std::setw(4) << _service->service_ << "."
                                << std::setw(4) << _service->instance_ << "."
                                << std::setw(4) << its_method << "]:"
                                << " using (" << std::dec
                                << its_entry->second.first << ", "
                                << std::dec << its_entry->second.second << ")";
                    }
                }
            } else {
                VSOMEIP_ERROR << "SOME/IP-TP configuration contains invalid entry. No valid method specified!";
            }
        }
    } catch (...) {
        // intentionally left empty
    }
}

void
configuration_impl::load_udp_receive_buffer_size(const configuration_element &_element) {
    const std::string its_buffer_size("udp-receive-buffer-size");
    try {
        if (_element.tree_.get_child_optional(its_buffer_size)) {
            if (is_configured_[ET_UDP_RECEIVE_BUFFER_SIZE]) {
                VSOMEIP_WARNING << "Multiple definitions of " << its_buffer_size
                        << " Ignoring definition from " << _element.name_;
            } else {
                const std::string its_data(_element.tree_.get_child(its_buffer_size).data());
                try {
                    udp_receive_buffer_size_ = std::stoi(its_data.c_str(), nullptr, 10);
                } catch (const std::exception &e) {
                    VSOMEIP_ERROR<< __func__ << ": " << its_buffer_size << " " << e.what();
                }
                is_configured_[ET_UDP_RECEIVE_BUFFER_SIZE] = true;
            }
        }
    } catch (...) {
        // intentionally left empty
    }
}

void configuration_impl::load_secure_services(const configuration_element &_element) {
    std::lock_guard<std::mutex> its_lock(secure_services_mutex_);
    try {
        auto its_services = _element.tree_.get_child("secure-services");
        for (auto i = its_services.begin(); i != its_services.end(); ++i)
            load_secure_service(i->second);
    } catch (...) {
        // intentionally left empty
    }
}

void configuration_impl::load_secure_service(const boost::property_tree::ptree &_tree) {
    try {
        service_t its_service(0);
        instance_t its_instance(0);

        for (auto i = _tree.begin(); i != _tree.end(); ++i) {
            std::string its_key(i->first);
            std::string its_value(i->second.data());
            std::stringstream its_converter;

            // Trim "its_value"
            if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
                its_converter << std::hex << its_value;
            } else {
                its_converter << std::dec << its_value;
            }

            if (its_key == "service") {
                its_converter >> its_service;
            } else if (its_key == "instance") {
                its_converter >> its_instance;
            }
        }

        if (its_service != 0 && its_instance != 0) {
            auto find_service = secure_services_.find(its_service);
            if (find_service != secure_services_.end()) {
                find_service->second.insert(its_instance);
            } else {
                secure_services_[its_service].insert(its_instance);
            }
        }

    } catch (...) {
        // Intentionally left empty
    }
}

std::shared_ptr<debounce_filter_impl_t>
configuration_impl::get_debounce(const std::string &_name,
        service_t _service, instance_t _instance, event_t _event) const {

    // Try to find application (client) specific debounce configuration
    auto found_application = applications_.find(_name);
    if (found_application != applications_.end()) {
        auto found_service = found_application->second.debounces_.find(_service);
        if (found_service != found_application->second.debounces_.end()) {
            auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                auto found_event = found_instance->second.find(_event);
                if (found_event != found_instance->second.end()) {
                    return found_event->second;
                }
            }
        }
    }

    // If no application specific configuration was found, search for a
    // generic
    auto found_service = debounces_.find(_service);
    if (found_service != debounces_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            auto found_event = found_instance->second.find(_event);
            if (found_event != found_instance->second.end()) {
                return found_event->second;
            }
        }
    }
    return nullptr;
}

void
configuration_impl::load_tcp_restart_settings(const configuration_element &_element) {
    const std::string tcp_restart_aborts_max("tcp-restart-aborts-max");
    const std::string tcp_connect_time_max("tcp-connect-time-max");

    try {
        if (_element.tree_.get_child_optional(tcp_restart_aborts_max)) {
            if (is_configured_[ET_TCP_RESTART_ABORTS_MAX]) {
                VSOMEIP_WARNING << "Multiple definitions for "
                        << tcp_restart_aborts_max
                        << " Ignoring definition from " << _element.name_;
            } else {
                is_configured_[ET_TCP_RESTART_ABORTS_MAX] = true;
                auto mpsl = _element.tree_.get_child(
                        tcp_restart_aborts_max);
                std::string s(mpsl.data());
                try {
                    tcp_restart_aborts_max_ =
                            static_cast<std::uint32_t>(std::stoul(
                                    s.c_str(), NULL, 10));
                } catch (const std::exception &e) {
                    VSOMEIP_ERROR<<__func__ << ": " << tcp_restart_aborts_max
                    << " " << e.what();
                }
            }
        }
        if (_element.tree_.get_child_optional(tcp_connect_time_max)) {
            if (is_configured_[ET_TCP_CONNECT_TIME_MAX]) {
                VSOMEIP_WARNING << "Multiple definitions for "
                        << tcp_connect_time_max
                        << " Ignoring definition from " << _element.name_;
            } else {
                is_configured_[ET_TCP_CONNECT_TIME_MAX] = true;
                auto mpsl = _element.tree_.get_child(tcp_connect_time_max);
                std::string s(mpsl.data());
                try {
                    tcp_connect_time_max_=
                            static_cast<std::uint32_t>(
                                    std::stoul(s.c_str(), NULL, 10));
                } catch (const std::exception &e) {
                    VSOMEIP_ERROR<< __func__ << ": "<< tcp_connect_time_max
                            << " " << e.what();
                }
            }
        }
    } catch (...) {
    }
}

std::uint32_t configuration_impl::get_max_tcp_restart_aborts() const {
    return tcp_restart_aborts_max_;
}

std::uint32_t configuration_impl::get_max_tcp_connect_time() const {
    return tcp_connect_time_max_;
}

bool configuration_impl::is_protected_device(
        const boost::asio::ip::address& _address) const {
    std::lock_guard<std::mutex> its_lock(sd_acceptance_required_ips_mutex_);
    return (sd_acceptance_rules_active_.find(_address)
            != sd_acceptance_rules_active_.end());
}

bool configuration_impl::is_protected_port(
        const boost::asio::ip::address& _address, std::uint16_t _port,
        bool _reliable) const {

    bool is_required(is_protected_device(_address));

    if (!is_required) {
        return false;
    }

    std::lock_guard<std::mutex> its_lock(sd_acceptance_required_ips_mutex_);
    const auto found_address = sd_acceptance_rules_.find(_address);
    if (found_address != sd_acceptance_rules_.end()) {
        const auto found_reliability = found_address->second.second.find(_reliable);
        if (found_reliability != found_address->second.second.end()) {
            const auto its_range = boost::icl::interval<std::uint16_t>::closed(_port, _port);

            bool is_optional
                = (found_reliability->second.first.find(its_range)
                   != found_reliability->second.first.end());

            bool is_secure
                = (found_reliability->second.second.find(its_range)
                   != found_reliability->second.second.end());

            is_required = is_optional || is_secure;
        }
    }

    return is_required;
}

bool configuration_impl::is_secure_port(
        const boost::asio::ip::address& _address, std::uint16_t _port,
        bool _reliable) const {

    bool is_secure(false);

    std::lock_guard<std::mutex> its_lock(sd_acceptance_required_ips_mutex_);
    const auto found_address = sd_acceptance_rules_.find(_address);
    if (found_address != sd_acceptance_rules_.end()) {
        const auto found_reliability
            = found_address->second.second.find(_reliable);
        if (found_reliability != found_address->second.second.end()) {
            const auto its_range
                = boost::icl::interval<std::uint16_t>::closed(_port, _port);
            return (found_reliability->second.second.find(its_range)
                    != found_reliability->second.second.end());
        }
    }

    return is_secure;
}

void configuration_impl::set_sd_acceptance_rule(
        const boost::asio::ip::address &_address,
        port_range_t _port_range, port_type_e _type,
        const std::string &_path, bool _reliable, bool _enable, bool _default) {

    (void)_port_range;
    (void)_type;

    std::lock_guard<std::mutex> its_lock(sd_acceptance_required_ips_mutex_);

    const auto its_optional_client = boost::icl::interval<std::uint16_t>::closed(30491, 30499);
    const auto its_optional_client_spare = boost::icl::interval<std::uint16_t>::closed(30898, 30998);
    const auto its_optional_server = boost::icl::interval<std::uint16_t>::closed(30501, 30599);

    const auto its_secure_client = boost::icl::interval<std::uint16_t>::closed(32491, 32499);
    const auto its_secure_client_spare = boost::icl::interval<std::uint16_t>::closed(32898, 32998);
    const auto its_secure_server = boost::icl::interval<std::uint16_t>::closed(32501, 32599);

    const bool rules_active = (sd_acceptance_rules_active_.find(_address)
            != sd_acceptance_rules_active_.end());

    const auto found_address = sd_acceptance_rules_.find(_address);
    if (found_address != sd_acceptance_rules_.end()) {
        if (found_address->second.first.length() > 0
                && found_address->second.first != _path) {
            VSOMEIP_WARNING << __func__ << ": activation path for IP: "
                    << _address << " differ: "
                    << found_address->second.first << " vs. " << _path
                    << " will use: " << found_address->second.first;
        } else {
            found_address->second.first = _path;
        }
        const auto found_reliability = found_address->second.second.find(_reliable);
        if (found_reliability != found_address->second.second.end()) {
            if (_enable) {
                // only insert full range interval if there are no other intervals
                // configured
                if (!_default ||
                        (found_reliability->second.first.empty()
                                && found_reliability->second.second.empty())) {
                    found_reliability->second.first.add(its_optional_client);
                    found_reliability->second.first.add(its_optional_client_spare);
                    found_reliability->second.first.add(its_optional_server);
                    found_reliability->second.second.add(its_secure_client);
                    found_reliability->second.second.add(its_secure_client_spare);
                    found_reliability->second.second.add(its_secure_server);
                    if (!rules_active) {
                        sd_acceptance_rules_active_.insert(_address);
                    }
                    VSOMEIP_INFO << "ipsec:acceptance:" << _address
                            << ":" << (_reliable ? "tcp" : "udp") << ": using default ranges "
                            << found_reliability->second.first << " "
                            << found_reliability->second.second;
                } else {
                    VSOMEIP_INFO << "ipsec:acceptance:" << _address
                            << ":" << (_reliable ? "tcp" : "udp") << ": using configured ranges "
                            << found_reliability->second.first << " "
                            << found_reliability->second.second;
                }
            } else {
                found_reliability->second.first.erase(its_optional_client);
                found_reliability->second.first.erase(its_optional_client_spare);
                found_reliability->second.first.erase(its_optional_server);
                found_reliability->second.second.erase(its_secure_client);
                found_reliability->second.second.erase(its_secure_client_spare);
                found_reliability->second.second.erase(its_secure_server);
                if (found_reliability->second.first.empty()
                        && found_reliability->second.second.empty()) {
                    found_address->second.second.erase(found_reliability);
                    if (found_address->second.second.empty()) {
                        sd_acceptance_rules_.erase(found_address);
                        if (rules_active) {// no more rules for IP present
                            sd_acceptance_rules_active_.erase(_address);
                        }
                    }
                }
            }
        } else if (_enable) {
            boost::icl::interval_set<std::uint16_t> its_optional_default;
            its_optional_default.add(its_optional_client);
            its_optional_default.add(its_optional_client_spare);
            its_optional_default.add(its_optional_server);
            boost::icl::interval_set<std::uint16_t> its_secure_default;
            its_secure_default.add(its_secure_client);
            its_secure_default.add(its_secure_client_spare);
            its_secure_default.add(its_secure_server);

            found_address->second.second.emplace(
                    std::make_pair(_reliable,
                            std::make_pair(its_optional_default, its_secure_default)));
            if (!rules_active) {
                sd_acceptance_rules_active_.insert(_address);
            }

            const auto found_reliability = found_address->second.second.find(_reliable);
            VSOMEIP_INFO << "ipsec:acceptance:" << _address
                    << ":" << (_reliable ? "tcp" : "udp") << ": using default ranges "
                    << found_reliability->second.first << " "
                    << found_reliability->second.second;
        }
    } else if (_enable) {
        boost::icl::interval_set<std::uint16_t> its_optional_default;
        its_optional_default.add(its_optional_client);
        its_optional_default.add(its_optional_client_spare);
        its_optional_default.add(its_optional_server);
        boost::icl::interval_set<std::uint16_t> its_secure_default;
        its_secure_default.add(its_secure_client);
        its_secure_default.add(its_secure_client_spare);
        its_secure_default.add(its_secure_server);

        sd_acceptance_rules_.emplace(std::make_pair(_address,
                std::make_pair(
                        _path,
                        std::map<
                            bool,
                            std::pair<
                                boost::icl::interval_set<std::uint16_t>,
                                boost::icl::interval_set<std::uint16_t>
                            >
                        >({{
                           _reliable,
                           std::make_pair(its_optional_default, its_secure_default)
                          }}))));
        if (!rules_active) {
            sd_acceptance_rules_active_.insert(_address);
        }

        const auto found_address = sd_acceptance_rules_.find(_address);
        if (found_address != sd_acceptance_rules_.end()) {
            const auto found_reliability = found_address->second.second.find(_reliable);
            if (found_reliability != found_address->second.second.end()) {
                VSOMEIP_INFO << "ipsec:acceptance:" << _address
                        << ":" << (_reliable ? "tcp" : "udp") << ": using default ranges "
                        << found_reliability->second.first << " "
                        << found_reliability->second.second;
            }
        }
    }
}

configuration::sd_acceptance_rules_t configuration_impl::get_sd_acceptance_rules() {
    std::lock_guard<std::mutex> its_lock(sd_acceptance_required_ips_mutex_);
    return sd_acceptance_rules_;
}

void configuration_impl::set_sd_acceptance_rules_active(
            const boost::asio::ip::address& _address, bool _enable) {
    std::lock_guard<std::mutex> its_lock(sd_acceptance_required_ips_mutex_);
    if (_enable) {
        sd_acceptance_rules_active_.insert(_address);
    } else {
        sd_acceptance_rules_active_.erase(_address);
    }
}

bool configuration_impl::is_secure_service(service_t _service, instance_t _instance) const {
    std::lock_guard<std::mutex> its_lock(secure_services_mutex_);
    const auto its_service = secure_services_.find(_service);
    if (its_service != secure_services_.end())
        return (its_service->second.find(_instance) != its_service->second.end());
    return false;
}

int configuration_impl::get_udp_receive_buffer_size() const {

    return udp_receive_buffer_size_;
}

bool configuration_impl::is_tp_client(
        service_t _service,
        instance_t _instance,
        method_t _method) const {

    bool ret(false);

    const auto its_service
        = find_service(_service, _instance);

    if (its_service) {
        ret = (its_service->tp_client_config_.find(_method)
                != its_service->tp_client_config_.end());
    }

    return ret;
}

bool configuration_impl::is_tp_service(
        service_t _service,
        instance_t _instance,
        method_t _method) const {

    bool ret(false);
    const auto its_service
        = find_service(_service, _instance);
    if (its_service) {
        ret = (its_service->tp_service_config_.find(_method)
                != its_service->tp_service_config_.end());
    }

    return ret;
}

void configuration_impl::get_tp_configuration(
        service_t _service, instance_t _instance, method_t _method,
        bool _is_client,
        std::uint16_t &_max_segment_length, std::uint32_t &_separation_time) const {

    const auto its_info = find_service(_service, _instance);
    if (its_info) {
        if (_is_client) {
            auto its_method = its_info->tp_client_config_.find(_method);

            // Note: The following two lines do not make sense now,
            // but they will when TP configuration is reworked
            if (its_method == its_info->tp_client_config_.end())
                its_method = its_info->tp_client_config_.find(ANY_METHOD);

            if (its_method != its_info->tp_client_config_.end()) {
                _max_segment_length = its_method->second.first;
                _separation_time = its_method->second.second;
                return;
            }
        } else {
            auto its_method = its_info->tp_service_config_.find(_method);

            // Note: The following two lines do not make sense now,
            // but they will when TP configuration is reworked
            if (its_method == its_info->tp_service_config_.end())
                its_method = its_info->tp_service_config_.find(ANY_METHOD);

            if (its_method != its_info->tp_service_config_.end()) {
                _max_segment_length = its_method->second.first;
                _separation_time = its_method->second.second;
                return;
            }
        }
    }

    // No configuration defined --> set default values
    _max_segment_length = VSOMEIP_TP_MAX_SEGMENT_LENGTH_DEFAULT;
    _separation_time = 0;
}

std::uint32_t configuration_impl::get_shutdown_timeout() const {
    return shutdown_timeout_;
}

bool configuration_impl::log_statistics() const {
    return log_statistics_;
}

uint32_t configuration_impl::get_statistics_interval() const {
    return statistics_interval_;
}

uint32_t configuration_impl::get_statistics_min_freq() const {
    return statistics_min_freq_;
}

uint32_t configuration_impl::get_statistics_max_messages() const {
    return statistics_max_messages_;
}

uint8_t configuration_impl::get_max_remote_subscribers() const {
    return max_remote_subscribers_;
}

partition_id_t
configuration_impl::get_partition_id(
        service_t _service, instance_t _instance) const {

    partition_id_t its_id(VSOMEIP_DEFAULT_PARTITION_ID);

    std::lock_guard<std::mutex> its_lock(partitions_mutex_);
    auto find_service = partitions_.find(_service);
    if (find_service != partitions_.end()) {
        auto find_instance = find_service->second.find(_instance);
        if (find_instance != find_service->second.end()) {
            its_id = find_instance->second;
        }
    }

    return its_id;
}

reliability_type_e
configuration_impl::get_reliability_type(
            const boost::asio::ip::address &_reliable_address,
            const uint16_t &_reliable_port,
            const boost::asio::ip::address &_unreliable_address,
            const uint16_t &_unreliable_port) const {

    if (_reliable_port != ILLEGAL_PORT
            && _unreliable_port != ILLEGAL_PORT
            && !_reliable_address.is_unspecified()
            && !_unreliable_address.is_unspecified()) {
        return reliability_type_e::RT_BOTH;
    } else if (_unreliable_port != ILLEGAL_PORT
            && !_unreliable_address.is_unspecified()) {
        return reliability_type_e::RT_UNRELIABLE;
    } else if (_reliable_port != ILLEGAL_PORT
            && !_reliable_address.is_unspecified()) {
        return reliability_type_e::RT_RELIABLE;
    }
    return reliability_type_e::RT_UNKNOWN;
}

bool
configuration_impl::is_security_enabled() const {

    return is_security_enabled_;
}

bool
configuration_impl::is_security_external() const {

    return is_security_external_;
}

bool
configuration_impl::is_security_audit() const {

    return is_security_audit_;
}

bool
configuration_impl::is_remote_access_allowed() const {

    return is_remote_access_allowed_;
}

std::shared_ptr<policy_manager_impl> configuration_impl::get_policy_manager() const {
    return policy_manager_;
}

std::shared_ptr<security> configuration_impl::get_security() const {
    return security_;
}

}  // namespace cfg
}  // namespace vsomeip_v3
