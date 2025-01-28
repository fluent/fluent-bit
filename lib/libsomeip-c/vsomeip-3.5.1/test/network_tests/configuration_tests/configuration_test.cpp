// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <cstdlib>
#include <iostream>

#include <gtest/gtest.h>

#include <common/utility.hpp>

#include <vsomeip/constants.hpp>
#include <vsomeip/plugins/application_plugin.hpp>
#include <vsomeip/internal/logger.hpp>
#include <vsomeip/internal/plugin_manager.hpp>
#include "../implementation/configuration/include/configuration.hpp"

#include "../../implementation/configuration/include/configuration_impl.hpp"
#include "../../implementation/configuration/include/configuration_plugin.hpp"
#include "../../implementation/protocol/include/protocol.hpp"
#include "../../implementation/security/include/policy_manager_impl.hpp"

namespace vsomeip = vsomeip_v3;

#define CONFIGURATION_FILE              "configuration_test.json"
#define DEPRECATED_CONFIGURATION_FILE   "configuration_test_deprecated.json"

#define EXPECTED_UNICAST_ADDRESS        "10.0.2.15"

#define EXPECTED_HAS_CONSOLE            true
#define EXPECTED_HAS_FILE                true
#define EXPECTED_HAS_DLT                false
#define EXPECTED_LOGLEVEL                "debug"
#define EXPECTED_LOGFILE                "/home/someip/another-file.log"

#define EXPECTED_ROUTING_MANAGER_HOST    "my_application"

// Logging
#define EXPECTED_VERSION_LOGGING_ENABLED                                    false
#define EXPECTED_VERSION_LOGGING_INTERVAL                                   15

// Application
#define EXPECTED_APPLICATION_MAX_DISPATCHERS                                25
#define EXPECTED_APPLICATION_MAX_DISPATCH_TIME                              1234
#define EXPECTED_APPLICATION_MAX_DETACHED_THREAD_WAIT_TIME                  3
#define EXPECTED_APPLICATION_THREADS                                        12
#define EXPECTED_APPLICATION_REQUEST_DEBOUNCE_TIME                          5000

// Services
#define EXPECTED_UNICAST_ADDRESS_1234_0022                                  EXPECTED_UNICAST_ADDRESS
#define EXPECTED_RELIABLE_PORT_1234_0022                                    30506
#define EXPECTED_UNRELIABLE_PORT_1234_0022                                  31000

#define EXPECTED_UNICAST_ADDRESS_1234_0023                                  EXPECTED_UNICAST_ADDRESS
#define EXPECTED_RELIABLE_PORT_1234_0023                                    30503
#define EXPECTED_UNRELIABLE_PORT_1234_0023                                  vsomeip::ILLEGAL_PORT

#define EXPECTED_UNICAST_ADDRESS_2277_0022                                  EXPECTED_UNICAST_ADDRESS
#define EXPECTED_RELIABLE_PORT_2277_0022                                    30505
#define EXPECTED_UNRELIABLE_PORT_2277_0022                                  31001

#define EXPECTED_UNICAST_ADDRESS_2266_0022                                  EXPECTED_UNICAST_ADDRESS
#define EXPECTED_RELIABLE_PORT_2266_0022                                    30505
#define EXPECTED_UNRELIABLE_PORT_2266_0022                                  30507

#define EXPECTED_UNICAST_ADDRESS_4466_0321                                  "10.0.2.23"
#define EXPECTED_RELIABLE_PORT_4466_0321                                    30506
#define EXPECTED_UNRELIABLE_PORT_4466_0321                                  30444

// Service Discovery
#define EXPECTED_SD_ENABLED                                                 true
#define EXPECTED_SD_PROTOCOL                                                "udp"
#define EXPECTED_SD_MULTICAST                                               "224.212.244.223"
#define EXPECTED_SD_PORT                                                    30666

#define EXPECTED_INITIAL_DELAY_MIN                                          1234
#define EXPECTED_INITIAL_DELAY_MAX                                          2345
#define EXPECTED_REPETITIONS_BASE_DELAY                                     4242
#define EXPECTED_REPETITIONS_MAX                                            4
#define EXPECTED_TTL                                                        13
#define EXPECTED_CYCLIC_OFFER_DELAY                                         2132
#define EXPECTED_REQUEST_RESPONSE_DELAY                                     1111

#define EXPECTED_DEPRECATED_INITIAL_DELAY_MIN                               10
#define EXPECTED_DEPRECATED_INITIAL_DELAY_MAX                               100
#define EXPECTED_DEPRECATED_REPETITIONS_BASE_DELAY                          200
#define EXPECTED_DEPRECATED_REPETITIONS_MAX                                 7
#define EXPECTED_DEPRECATED_TTL                                             5
#define EXPECTED_DEPRECATED_REQUEST_RESPONSE_DELAY                          2001

template<class T>
::testing::AssertionResult check(const T &_is, const T &_expected, const std::string &_test) {
    if (_is == _expected) {
        return ::testing::AssertionSuccess() << "Test \"" << _test << "\" succeeded.";
    } else {
        return ::testing::AssertionFailure() << "Test \"" << _test << "\" failed! ("
                      << _is << " != " << _expected << ")";
    }
}

std::string loglevel_to_string(vsomeip::logger::level_e &_level) {
    switch (_level) {
    case vsomeip::logger::level_e::LL_FATAL:
        return "fatal";
    case vsomeip::logger::level_e::LL_ERROR:
        return "error";
    case vsomeip::logger::level_e::LL_WARNING:
        return "warning";
    case vsomeip::logger::level_e::LL_INFO:
        return "info";
    case vsomeip::logger::level_e::LL_DEBUG:
        return "debug";
    case vsomeip::logger::level_e::LL_VERBOSE:
        return "verbose";
    default:
        return "unknown";
    }
}

void check_file(const std::string &_config_file,
                const std::string &_expected_unicast_address,
                bool _expected_has_console,
                bool _expected_has_file,
                bool _expected_has_dlt,
                bool _expected_version_logging_enabled,
                uint32_t _expected_version_logging_interval,
                uint32_t _expected_application_max_dispatcher,
                uint32_t _expected_application_max_dispatch_time,
                uint32_t _expected_application_max_detached_thread_wait_time,
                uint32_t _expected_application_threads,
                uint32_t _expected_application_request_debounce_time,
                const std::string &_expected_logfile,
                const std::string &_expected_loglevel,
                const std::string &_expected_unicast_address_1234_0022,
                uint16_t _expected_reliable_port_1234_0022,
                uint16_t _expected_unreliable_port_1234_0022,
                const std::string &_expected_unicast_address_1234_0023,
                uint16_t _expected_reliable_port_1234_0023,
                uint16_t _expected_unreliable_port_1234_0023,
                const std::string &_expected_unicast_address_2277_0022,
                uint16_t _expected_reliable_port_2277_0022,
                uint16_t _expected_unreliable_port_2277_0022,
                const std::string &_expected_unicast_address_2266_0022,
                uint16_t _expected_reliable_port_2266_0022,
                uint16_t _expected_unreliable_port_2266_0022,
                const std::string &_expected_unicast_address_4466_0321,
                uint16_t _expected_reliable_port_4466_0321,
                uint16_t _expected_unreliable_port_4466_0321,
                bool _expected_enabled,
                const std::string &_expected_protocol,
                const std::string &_expected_multicast,
                uint16_t _expected_port,
                uint32_t _expected_initial_delay_min,
                uint32_t _expected_initial_delay_max,
                int32_t _expected_repetitions_base_delay,
                uint8_t _expected_repetitions_max,
                vsomeip::ttl_t _expected_ttl,
                vsomeip::ttl_t _expected_cyclic_offer_delay,
                vsomeip::ttl_t _expected_request_response_delay) {


    // 0. Set environment variable to config file and load it
#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
    setenv("VSOMEIP_CONFIGURATION", _config_file.c_str(), 1);
#else
    _putenv_s("VSOMEIP_CONFIGURATION", _config_file.c_str()
#endif

    // 1. Create configuration object
    std::shared_ptr<vsomeip::configuration> its_configuration;
    auto its_plugin = vsomeip::plugin_manager::get()->get_plugin(
            vsomeip::plugin_type_e::CONFIGURATION_PLUGIN, VSOMEIP_CFG_LIBRARY);
    if (its_plugin) {
        auto its_configuration_plugin
            = std::dynamic_pointer_cast<vsomeip::configuration_plugin>(its_plugin);
        if (its_configuration_plugin)
            its_configuration = its_configuration_plugin->get_configuration(EXPECTED_ROUTING_MANAGER_HOST, "");
    }

    // 2. Did we get a configuration object?
    if (0 == its_configuration) {
        ADD_FAILURE() << "No configuration object. "
                "Either memory overflow or loading error detected!";
        return;
    }

    // Check "suppress_missing_event_logs"
    EXPECT_TRUE(its_configuration->check_suppress_events(0x0023, 0x0001, 0x8002));  // Multiple values
    EXPECT_TRUE(its_configuration->check_suppress_events(0x0023, 0x0001, 0x8015));  // Range
    EXPECT_FALSE(its_configuration->check_suppress_events(0x0023, 0x0001, 0x8016)); // Range
    EXPECT_TRUE(its_configuration->check_suppress_events(0x0023, 0x0001, 0x8020));  // Single

    EXPECT_TRUE(its_configuration->check_suppress_events(0x0023, 0x0002, 0x8005));  // Single
    EXPECT_FALSE(its_configuration->check_suppress_events(0x0023, 0x0002, 0x8006));  // Single

    EXPECT_TRUE(its_configuration->check_suppress_events(0x1111, 0x00f2, 0x8001));  // "ANY" Service/Event
    EXPECT_TRUE(its_configuration->check_suppress_events(0x0102, 0x0010, 0x8005));  // "ANY" Instance
    EXPECT_FALSE(its_configuration->check_suppress_events(0x0102, 0x0010, 0x8007)); // "ANY" Instance

    EXPECT_TRUE(its_configuration->check_suppress_events(0x0024, 0x5555, 0x8011));  // "ANY" INSTANCE
    EXPECT_FALSE(its_configuration->check_suppress_events(0x0024, 0x5555, 0x8016)); // "ANY" INSTANCE

    vsomeip::cfg::configuration_impl its_copied_config(
            static_cast<vsomeip::cfg::configuration_impl&>(*its_configuration));
    vsomeip::cfg::configuration_impl* its_new_config =
            new vsomeip::cfg::configuration_impl(its_copied_config);
    delete its_new_config;

    its_configuration->set_configuration_path("/my/test/path");

    // 3. Check host address
    boost::asio::ip::address its_host_unicast_address
        = its_configuration->get_unicast_address();
    EXPECT_TRUE(check<std::string>(its_host_unicast_address.to_string(),
                       _expected_unicast_address, "UNICAST ADDRESS"));
    EXPECT_TRUE(its_configuration->is_v4());
    EXPECT_FALSE(its_configuration->is_v6());

    // check diagnosis prefix
    EXPECT_NE(0x54, its_configuration->get_diagnosis_address());
    EXPECT_EQ(0x55, its_configuration->get_diagnosis_address());
    EXPECT_NE(0x56, its_configuration->get_diagnosis_address());

    // 4. Check logging
    bool has_console = its_configuration->has_console_log();
    bool has_file = its_configuration->has_file_log();
    bool has_dlt = its_configuration->has_dlt_log();
    std::string logfile = its_configuration->get_logfile();
    vsomeip::logger::level_e loglevel
        = its_configuration->get_loglevel();
    bool has_version_logging = its_configuration->log_version();
    std::uint32_t version_logging_interval = its_configuration->get_log_version_interval();

    EXPECT_TRUE(check<bool>(has_console, _expected_has_console, "HAS CONSOLE"));
    EXPECT_TRUE(check<bool>(has_file, _expected_has_file, "HAS FILE"));
    EXPECT_TRUE(check<bool>(has_dlt, _expected_has_dlt, "HAS DLT"));
    EXPECT_TRUE(check<std::string>(logfile, _expected_logfile, "LOGFILE"));
    EXPECT_TRUE(check<std::string>(loglevel_to_string(loglevel),
                       _expected_loglevel, "LOGLEVEL"));
    EXPECT_TRUE(check<bool>(has_version_logging, _expected_version_logging_enabled,
                    "VERSION LOGGING"));
    EXPECT_TRUE(check<uint32_t>(version_logging_interval,
                    _expected_version_logging_interval,
                    "VERSION LOGGING INTERVAL"));

    // watchdog
    EXPECT_TRUE(its_configuration->is_watchdog_enabled());
    EXPECT_EQ(1234u, its_configuration->get_watchdog_timeout());
    EXPECT_EQ(7u, its_configuration->get_allowed_missing_pongs());

    // file permissions
    EXPECT_EQ(0222u, its_configuration->get_permissions_uds());

    // selective broadcasts
    EXPECT_TRUE(its_configuration->supports_selective_broadcasts(
            boost::asio::ip::address::from_string("160.160.160.160")));

    // tracing
    std::shared_ptr<vsomeip::cfg::trace> its_trace = its_configuration->get_trace();
    EXPECT_TRUE(its_trace->is_enabled_);
    EXPECT_TRUE(its_trace->is_sd_enabled_);
    EXPECT_EQ(4u, its_trace->channels_.size());
    EXPECT_TRUE(its_trace->filters_.size() == 2u || its_trace->filters_.size() == 4u);
    for (const auto &c : its_trace->channels_) {
        EXPECT_TRUE(c->name_ == std::string("testname") || c->name_ == std::string("testname2") ||
            c->name_ == std::string("testname3") || c->name_ == std::string("testname4"));
        if (c->name_ == std::string("testname")) {
            EXPECT_EQ(std::string("testid"), c->id_);
        } else if (c->name_ == std::string("testname2")) {
            EXPECT_EQ(std::string("testid2"), c->id_);
        } else if (c->name_ == std::string("testname3")) {
            EXPECT_EQ(std::string("testid3"), c->id_);
        } else if (c->name_ == std::string("testname4")) {
            EXPECT_EQ(std::string("testid4"), c->id_);
        }
    }
    for (const auto &f : its_trace->filters_) {
        auto its_channel_name = f->channels_.front();
        auto its_matches = f->matches_;
        EXPECT_TRUE(its_channel_name == std::string("testname") || its_channel_name == std::string("testname2") ||
            its_channel_name == std::string("testname3") || its_channel_name == std::string("testname4"));
        if (its_channel_name == std::string("testname")) {
            EXPECT_EQ(2u, its_matches.size());

            for (const vsomeip::trace::match_t &m : its_matches) {
                EXPECT_TRUE(std::get<0>(m) == vsomeip::service_t(0x1111) ||
                    std::get<0>(m) == vsomeip::service_t(2222));
                EXPECT_TRUE(std::get<1>(m) == vsomeip::instance_t(0xffff));
                EXPECT_TRUE(std::get<2>(m) == vsomeip::method_t(0xffff));
                EXPECT_EQ(f->ftype_, vsomeip_v3::trace::filter_type_e::POSITIVE);
                EXPECT_FALSE(f->is_range_);
            }
        } else if (its_channel_name == std::string("testname2")) {
            EXPECT_EQ(2u, its_matches.size());

            for (const vsomeip::trace::match_t &m : its_matches) {
                EXPECT_TRUE(std::get<0>(m) == vsomeip::service_t(0x3333) ||
                    std::get<0>(m) == vsomeip::service_t(4444));
                EXPECT_TRUE(std::get<1>(m) == vsomeip::instance_t(0xffff));
                EXPECT_TRUE(std::get<2>(m) == vsomeip::method_t(0xffff));
                EXPECT_NE(f->ftype_, vsomeip_v3::trace::filter_type_e::POSITIVE);
                EXPECT_FALSE(f->is_range_);
            }
        } else if (its_channel_name == std::string("testname3")) {
            EXPECT_EQ(2u, its_matches.size());

            for (const vsomeip::trace::match_t &m : its_matches) {
                EXPECT_TRUE(std::get<0>(m) == vsomeip::service_t(0x1111) ||
                    std::get<0>(m) == vsomeip::service_t(0x3333));
                EXPECT_TRUE(std::get<1>(m) == vsomeip::instance_t(0xffff));
                EXPECT_TRUE(std::get<2>(m) == vsomeip::method_t(0xffff) ||
                    std::get<2>(m) == vsomeip::method_t(0x8888));
                EXPECT_NE(f->ftype_, vsomeip_v3::trace::filter_type_e::POSITIVE);
                EXPECT_FALSE(f->is_range_);
            }
        } else if (its_channel_name == std::string("testname4")) {
            EXPECT_EQ(2u, its_matches.size());

            for (const vsomeip::trace::match_t &m : its_matches) {
                EXPECT_TRUE(std::get<0>(m) == vsomeip::service_t(0x1111) ||
                    std::get<0>(m) == vsomeip::service_t(0x3333));
                EXPECT_TRUE(std::get<1>(m) == vsomeip::instance_t(0x0001));
                EXPECT_TRUE(std::get<2>(m) == vsomeip::method_t(0xffff) ||
                    std::get<2>(m) == vsomeip::method_t(0x8888));
                EXPECT_NE(f->ftype_, vsomeip_v3::trace::filter_type_e::POSITIVE);
                EXPECT_TRUE(f->is_range_);
            }
        }
    }

    // Applications
    std::size_t max_dispatchers = its_configuration->get_max_dispatchers(
            EXPECTED_ROUTING_MANAGER_HOST);
    std::size_t max_dispatch_time = its_configuration->get_max_dispatch_time(
            EXPECTED_ROUTING_MANAGER_HOST);
    std::size_t max_detached_thread_wait_time = its_configuration->get_max_detached_thread_wait_time(
            EXPECTED_ROUTING_MANAGER_HOST);
    std::size_t io_threads = its_configuration->get_io_thread_count(
            EXPECTED_ROUTING_MANAGER_HOST);
    std::size_t request_time = its_configuration->get_request_debouncing(
            EXPECTED_ROUTING_MANAGER_HOST);

    EXPECT_TRUE(check<std::size_t>(max_dispatchers,
            _expected_application_max_dispatcher, "MAX DISPATCHERS"));
    EXPECT_TRUE(check<std::size_t>(max_dispatch_time,
            _expected_application_max_dispatch_time, "MAX DISPATCH TIME"));
    EXPECT_TRUE(check<std::size_t>(max_detached_thread_wait_time,
            _expected_application_max_detached_thread_wait_time, "MAX DETACHED THREADS WAIT TIME"));
    EXPECT_TRUE(check<std::size_t>(io_threads, _expected_application_threads,
            "IO THREADS"));
    EXPECT_TRUE(check<std::size_t>(request_time,
            _expected_application_request_debounce_time, "REQUEST DEBOUNCE TIME"));

    EXPECT_EQ(0x9933, its_configuration->get_id("other_application"));

    std::map<vsomeip::plugin_type_e, std::set<std::string>> its_plugins =
            its_configuration->get_plugins(EXPECTED_ROUTING_MANAGER_HOST);
    EXPECT_EQ(1u, its_plugins.size());
    for (const auto& plugin : its_plugins) {
        EXPECT_EQ(vsomeip::plugin_type_e::APPLICATION_PLUGIN, plugin.first);
        for (const auto& its_library : plugin.second)
            EXPECT_EQ(std::string("libtestlibraryname.so." + std::to_string(VSOMEIP_APPLICATION_PLUGIN_VERSION)), its_library);
    }
    EXPECT_EQ(vsomeip::plugin_type_e::CONFIGURATION_PLUGIN, its_plugin->get_plugin_type());
    EXPECT_EQ("vsomeip-configuration-plugin", its_plugin->get_plugin_name());
    EXPECT_EQ(1u, its_plugin->get_plugin_version());


    // 5. Services
    std::string its_unicast_address
        = its_configuration->get_unicast_address(0x1234, 0x0022);
    uint16_t its_reliable_port
        = its_configuration->get_reliable_port(0x1234, 0x0022);
    uint16_t its_unreliable_port
        = its_configuration->get_unreliable_port(0x1234, 0x0022);

    EXPECT_TRUE(check<std::string>(its_unicast_address,
            _expected_unicast_address_1234_0022,
            "UNICAST_ADDRESS_1234_0022"));
    EXPECT_TRUE(check<uint16_t>(its_reliable_port,
            _expected_reliable_port_1234_0022,
            "RELIABLE_PORT_1234_0022"));
    EXPECT_TRUE(check<uint16_t>(its_unreliable_port,
            _expected_unreliable_port_1234_0022,
            "UNRELIABLE_PORT_1234_0022"));

    its_unicast_address
        = its_configuration->get_unicast_address(0x1234, 0x0023);
    its_reliable_port
        = its_configuration->get_reliable_port(0x1234, 0x0023);
    its_unreliable_port
        = its_configuration->get_unreliable_port(0x1234, 0x0023);

    EXPECT_TRUE(check<std::string>(its_unicast_address,
            _expected_unicast_address_1234_0023,
            "UNICAST_ADDRESS_1234_0023"));
    EXPECT_TRUE(check<uint16_t>(its_reliable_port,
            _expected_reliable_port_1234_0023,
            "RELIABLE_PORT_1234_0023"));
    EXPECT_TRUE(check<uint16_t>(its_unreliable_port,
            _expected_unreliable_port_1234_0023,
            "UNRELIABLE_PORT_1234_0023"));

    its_unicast_address
        = its_configuration->get_unicast_address(0x2277, 0x0022);
    its_reliable_port
        = its_configuration->get_reliable_port(0x2277, 0x0022);
    its_unreliable_port
        = its_configuration->get_unreliable_port(0x2277, 0x0022);

    EXPECT_TRUE(check<std::string>(its_unicast_address,
            _expected_unicast_address_2277_0022,
            "UNICAST_ADDRESS_2277_0022"));
    EXPECT_TRUE(check<uint16_t>(its_reliable_port,
            _expected_reliable_port_2277_0022,
            "RELIABLE_PORT_2277_0022"));
    EXPECT_TRUE(check<uint16_t>(its_unreliable_port,
            _expected_unreliable_port_2277_0022,
            "UNRELIABLE_PORT_2277_0022"));

    its_unicast_address
        = its_configuration->get_unicast_address(0x2266, 0x0022);
    its_reliable_port
        = its_configuration->get_reliable_port(0x2266, 0x0022);
    its_unreliable_port
        = its_configuration->get_unreliable_port(0x2266, 0x0022);

    EXPECT_TRUE(check<std::string>(its_unicast_address,
            _expected_unicast_address_2266_0022,
            "UNICAST_ADDRESS_2266_0022"));
    EXPECT_TRUE(check<uint16_t>(its_reliable_port,
            _expected_reliable_port_2266_0022,
            "RELIABLE_PORT_2266_0022"));
    EXPECT_TRUE(check<uint16_t>(its_unreliable_port,
            _expected_unreliable_port_2266_0022,
            "UNRELIABLE_PORT_2266_0022"));

    its_unicast_address
        = its_configuration->get_unicast_address(0x4466, 0x0321);
    its_reliable_port
        = its_configuration->get_reliable_port(0x4466, 0x0321);
    its_unreliable_port
        = its_configuration->get_unreliable_port(0x4466, 0x0321);

    EXPECT_TRUE(check<std::string>(its_unicast_address,
            _expected_unicast_address_4466_0321,
            "UNICAST_ADDRESS_4466_0321"));
    EXPECT_TRUE(check<uint16_t>(its_reliable_port,
            _expected_reliable_port_4466_0321,
            "RELIABLE_PORT_4466_0321"));
    EXPECT_TRUE(check<uint16_t>(its_unreliable_port,
            _expected_unreliable_port_4466_0321,
            "UNRELIABLE_PORT_4466_0321"));

    std::string its_multicast_address;
    std::uint16_t its_multicast_port;
    its_configuration->get_multicast(0x7809, 0x1, 0x1111,
            its_multicast_address, its_multicast_port);
    EXPECT_EQ(1234u, its_multicast_port);
    EXPECT_EQ(std::string("224.212.244.225"), its_multicast_address);
    EXPECT_EQ(8u, its_configuration->get_threshold(0x7809, 0x1, 0x1111));

    EXPECT_TRUE(its_configuration->is_offered_remote(0x1234,0x0022));
    EXPECT_FALSE(its_configuration->is_offered_remote(0x3333,0x1));

    EXPECT_TRUE(its_configuration->has_enabled_magic_cookies("10.0.2.15", 30506));
    EXPECT_FALSE(its_configuration->has_enabled_magic_cookies("10.0.2.15", 30503));

    std::set<std::pair<vsomeip::service_t, vsomeip::instance_t>> its_remote_services =
            its_configuration->get_remote_services();
    EXPECT_EQ(1u, its_remote_services.size());
    for (const auto &p : its_remote_services) {
        EXPECT_EQ(0x4466, p.first);
        EXPECT_EQ(0x321, p.second);
    }

    EXPECT_TRUE(its_configuration->is_someip(0x3333,0x1));
    EXPECT_FALSE(its_configuration->is_someip(0x3555,0x1));

    // Internal services
    EXPECT_TRUE(its_configuration->is_local_service(0x1234, 0x0022));
    EXPECT_TRUE(its_configuration->is_local_service(0x3333,0x1));
    // defined range, service level only
    EXPECT_FALSE(its_configuration->is_local_service(0xF0FF,0x1));
    EXPECT_TRUE(its_configuration->is_local_service(0xF100,0x1));
    EXPECT_TRUE(its_configuration->is_local_service(0xF101,0x23));
    EXPECT_TRUE(its_configuration->is_local_service(0xF109,0xFFFF));
    EXPECT_FALSE(its_configuration->is_local_service(0xF10a,0x1));
    // defined range, service and instance level
    EXPECT_FALSE(its_configuration->is_local_service(0xF2FF,0xFFFF));
    EXPECT_TRUE(its_configuration->is_local_service(0xF300,0x1));
    EXPECT_TRUE(its_configuration->is_local_service(0xF300,0x5));
    EXPECT_TRUE(its_configuration->is_local_service(0xF300,0x10));
    EXPECT_FALSE(its_configuration->is_local_service(0xF300,0x11));
    EXPECT_FALSE(its_configuration->is_local_service(0xF301,0x11));

    // clients
    std::map<bool, std::set<uint16_t>> used_ports;
    used_ports[true].insert(0x11);
    used_ports[false].insert(0x10);
    std::uint16_t port_to_use(0x0);
    EXPECT_TRUE(its_configuration->get_client_port(0x8888, 0x1, vsomeip::ILLEGAL_PORT, true, used_ports, port_to_use));
    EXPECT_EQ(0x10, port_to_use);
    EXPECT_TRUE(its_configuration->get_client_port(0x8888, 0x1, vsomeip::ILLEGAL_PORT, false, used_ports, port_to_use));
    EXPECT_EQ(0x11, port_to_use);

    used_ports[true].insert(0x10);
    used_ports[false].insert(0x11);
    EXPECT_FALSE(its_configuration->get_client_port(0x8888, 0x1, vsomeip::ILLEGAL_PORT, true, used_ports, port_to_use));
    EXPECT_EQ(vsomeip::ILLEGAL_PORT, port_to_use);
    EXPECT_FALSE(its_configuration->get_client_port(0x8888, 0x1, vsomeip::ILLEGAL_PORT, false, used_ports, port_to_use));
    EXPECT_EQ(vsomeip::ILLEGAL_PORT, port_to_use);


    //check for correct client port assignment if service / instance was not configured but a remote port range
    used_ports.clear();
    EXPECT_TRUE(its_configuration->get_client_port(0x8888, 0x12, 0x7725, true, used_ports, port_to_use));
    EXPECT_EQ(0x771B, port_to_use);
    used_ports[true].insert(0x771B);
    EXPECT_TRUE(its_configuration->get_client_port(0x8888, 0x12, 0x7725, true, used_ports, port_to_use));
    EXPECT_EQ(0x771C, port_to_use);
    used_ports[true].insert(0x771C);
    EXPECT_TRUE(its_configuration->get_client_port(0x8888, 0x12, 0x7B0D, true, used_ports, port_to_use));
    EXPECT_EQ(0x7B03, port_to_use);
    used_ports[true].insert(0x7B03);
    EXPECT_TRUE(its_configuration->get_client_port(0x8888, 0x12, 0x7B0D, true, used_ports, port_to_use));
    EXPECT_EQ(0x7B04, port_to_use);
    used_ports[true].insert(0x7B04);
    EXPECT_TRUE(its_configuration->get_client_port(0x8888, 0x12, 0x7EF4, true, used_ports, port_to_use));
    EXPECT_EQ(0x7EEB, port_to_use);
    used_ports[true].insert(0x7EEB);
    EXPECT_TRUE(its_configuration->get_client_port(0x8888, 0x12, 0x7EF4, true, used_ports, port_to_use));
    EXPECT_EQ(0x7EEC, port_to_use);
    used_ports[true].insert(0x7EEC);
    used_ports.clear();


    // payload sizes
    // use 17000 instead of 1500 as configured max-local-payload size will be
    // increased to bigger max-reliable-payload-size
    std::uint32_t max_local_message_size(
            17000u + 16u + vsomeip::protocol::SEND_COMMAND_HEADER_SIZE);
    EXPECT_EQ(max_local_message_size, its_configuration->get_max_message_size_local());
    EXPECT_EQ(11u, its_configuration->get_buffer_shrink_threshold());
    EXPECT_EQ(14999u + 16u, its_configuration->get_max_message_size_reliable("10.10.10.10", 7777));
    EXPECT_EQ(17000u + 16, its_configuration->get_max_message_size_reliable("11.11.11.11", 4711));
    EXPECT_EQ(15001u + 16, its_configuration->get_max_message_size_reliable("10.10.10.11", 7778));

    // security
#if !defined(VSOMEIP_DISABLE_SECURITY) && !defined(__QNX__)
    vsomeip_sec_client_t its_x123_x456 = utility::create_uds_client(0x123, 0x456, 0);

    EXPECT_TRUE(its_configuration->check_routing_credentials(0x7788, &its_x123_x456));

    // GID does not match
    vsomeip_sec_client_t its_x123_x222 = utility::create_uds_client(0x123, 0x222, 0);
    EXPECT_FALSE(its_configuration->check_routing_credentials(0x7788, &its_x123_x222));

    // UID does not match
    vsomeip_sec_client_t its_x333_x456 = utility::create_uds_client(0x333, 0x456, 0);
    EXPECT_FALSE(its_configuration->check_routing_credentials(0x7788, &its_x333_x456));

    // client is not the routing manager
    vsomeip_sec_client_t its_x888_x999 = utility::create_uds_client(0x888, 0x999, 0);
    EXPECT_TRUE(its_configuration->check_routing_credentials(0x7777, &its_x888_x999));

    EXPECT_TRUE(its_configuration->is_security_enabled());
    vsomeip_sec_client_t its_1000_1000 = utility::create_uds_client(1000, 1000, 0);
    vsomeip_sec_client_t its_1001_1001 = utility::create_uds_client(1001, 1001, 0);
    vsomeip_sec_client_t its_2000_2000 = utility::create_uds_client(2000, 2000, 0);
    vsomeip_sec_client_t its_2001_2001 = utility::create_uds_client(2001, 2001, 0);
    vsomeip_sec_client_t its_4000_4000 = utility::create_uds_client(4000, 4000, 0);
    vsomeip_sec_client_t its_4001_4001 = utility::create_uds_client(4001, 4001, 0);
    vsomeip_sec_client_t its_5000_5000 = utility::create_uds_client(5000, 5000, 0);
    vsomeip_sec_client_t its_6000_6000 = utility::create_uds_client(6000, 6000, 0);
    vsomeip_sec_client_t its_7000_7000 = utility::create_uds_client(7000, 7000, 0);
    vsomeip_sec_client_t its_8000_8000 = utility::create_uds_client(8000, 8000, 0);
    vsomeip_sec_client_t its_9000_9000 = utility::create_uds_client(9000, 9000, 0);

    auto its_security = its_configuration->get_policy_manager();
    EXPECT_TRUE(its_security->is_offer_allowed(&its_1000_1000, 0x1234, 0x5678));
    EXPECT_TRUE(its_security->is_offer_allowed(&its_1000_1000, 0x1235, 0x5678));
    EXPECT_TRUE(its_security->is_offer_allowed(&its_1000_1000, 0x1236, 0x5678));
    EXPECT_TRUE(its_security->is_offer_allowed(&its_1000_1000, 0x1236, 0x5676));

    EXPECT_FALSE(its_security->is_offer_allowed(&its_1000_1000, 0x1236, 0x5679));
    EXPECT_FALSE(its_security->is_offer_allowed(&its_1000_1000, 0x1234, 0x5679));
    EXPECT_FALSE(its_security->is_offer_allowed(&its_1000_1000, 0x1233, 0x5679));
    EXPECT_FALSE(its_security->is_offer_allowed(&its_1001_1001, 0x1233, 0x5679));
    // explicitly denied offers
    EXPECT_FALSE(its_security->is_offer_allowed(&its_4000_4000, 0x1234, 0x5678));
    EXPECT_FALSE(its_security->is_offer_allowed(&its_4000_4000, 0x1235, 0x5678));
    EXPECT_TRUE(its_security->is_offer_allowed(&its_4000_4000, 0x1234, 0x5679));
    EXPECT_TRUE(its_security->is_offer_allowed(&its_4000_4000, 0x1300, 0x1));
    EXPECT_TRUE(its_security->is_offer_allowed(&its_4000_4000, 0x1300, 0x2));
    EXPECT_FALSE(its_security->is_offer_allowed(&its_4000_4000, 0x1236, 0x5678));
    EXPECT_FALSE(its_security->is_offer_allowed(&its_4000_4000, 0x1236, 0x5675));
    EXPECT_FALSE(its_security->is_offer_allowed(&its_4000_4000, 0x1236, 0x5676));
    EXPECT_FALSE(its_security->is_offer_allowed(&its_4000_4000, 0x1236, 0x5677));
    EXPECT_TRUE(its_security->is_offer_allowed(&its_4000_4000, 0x1236, 0x5679));

    // explicitly allowed requests of methods / events
    EXPECT_TRUE(its_security->is_client_allowed(&its_2000_2000, 0x1234, 0x5678, 0x0001));
    EXPECT_TRUE(its_security->is_client_allowed(&its_2000_2000, 0x1234, 0x5678, 0x8002));
    EXPECT_TRUE(its_security->is_client_allowed(&its_2000_2000, 0x1234, 0x5688, 0x8002));
    EXPECT_TRUE(its_security->is_client_allowed(&its_2000_2000, 0x1234, 0x5699, 0x8006));
    EXPECT_TRUE(its_security->is_client_allowed(&its_2000_2000, 0x1234, 0x5699, 0x8001));

    EXPECT_FALSE(its_security->is_client_allowed(&its_2001_2001, 0x1234, 0x5678, 0xFFFF));
    EXPECT_FALSE(its_security->is_client_allowed(&its_2001_2001, 0x1234, 0x5678, 0xFFFF));
    EXPECT_FALSE(its_security->is_client_allowed(&its_2000_2000, 0x1234, 0x5677, 0xFFFF));
    EXPECT_FALSE(its_security->is_client_allowed(&its_2000_2000, 0x1234, 0x5700, 0x0001));
    EXPECT_FALSE(its_security->is_client_allowed(&its_2000_2000, 0x1234, 0x5699, 0x8007));
    EXPECT_FALSE(its_security->is_client_allowed(&its_2000_2000, 0x1234, 0x5700, 0xFFFF));
    EXPECT_FALSE(its_security->is_client_allowed(&its_2000_2000, 0x1230, 0x5678, 0x0001));
    EXPECT_FALSE(its_security->is_client_allowed(&its_2000_2000, 0x1230, 0x5678, 0xFFFF));
    EXPECT_FALSE(its_security->is_client_allowed(&its_4000_4000, 0x1234, 0x5678, 0x0002));
    EXPECT_FALSE(its_security->is_client_allowed(&its_4000_4000, 0x1234, 0x5678, 0xFFFF));
    EXPECT_TRUE(its_security->is_client_allowed(&its_4000_4000, 0x1234, 0x5679, 0x0003));
    EXPECT_FALSE(its_security->is_client_allowed(&its_4000_4000, 0x1234, 0x5679, 0xFFFF));
    EXPECT_FALSE(its_security->is_client_allowed(&its_4000_4000, 0x1234, 0x5699, 0x9001));
    EXPECT_FALSE(its_security->is_client_allowed(&its_4000_4000, 0x1234, 0x5699, 0x9006));
    EXPECT_FALSE(its_security->is_client_allowed(&its_4001_4001, 0x1234, 0x5678, 0xFFFF));
    EXPECT_FALSE(its_security->is_client_allowed(&its_4001_4001, 0x1234, 0x5678, 0xFFFF));

    // check that any method ID is allowed
    EXPECT_TRUE(its_security->is_client_allowed(&its_2000_2000, 0x1237, 0x5678, 0x0001));
    EXPECT_TRUE(its_security->is_client_allowed(&its_2000_2000, 0x1237, 0x5678, 0xFFFF));

    // check that any instance ID is allowed but only one method ID
    EXPECT_TRUE(its_security->is_client_allowed(&its_2000_2000, 0x1238, 0x0004, 0x0001));
    EXPECT_FALSE(its_security->is_client_allowed(&its_2000_2000, 0x1238, 0x0004, 0x0002));

    // DENY NOTHING policy
    // check that ANY_METHOD is allowed in a "deny nothing" policy
    EXPECT_TRUE(its_security->is_client_allowed(&its_5000_5000, 0x1234, 0x5678, 0xFFFF));
    // check that specific method ID is allowed in a "deny nothing" policy
    EXPECT_TRUE(its_security->is_client_allowed(&its_5000_5000, 0x1234, 0x5678, 0x0001));

    // ALLOW NOTHING policy
    // check that ANY_METHOD is denied in a "allow nothing" policy
    EXPECT_FALSE(its_security->is_client_allowed(&its_6000_6000, 0x1234, 0x5678, 0xFFFF));
    // check that specific method ID is denied in a "allow nothing" policy
    EXPECT_FALSE(its_security->is_client_allowed(&its_6000_6000, 0x1234, 0x5678, 0x0001));

    // DENY only one service instance and ANY_METHOD (0x01 - 0xFFFF) policy
    EXPECT_FALSE(its_security->is_client_allowed(&its_7000_7000, 0x1234, 0x5678, 0xFFFF));
    EXPECT_FALSE(its_security->is_client_allowed(&its_7000_7000, 0x1234, 0x5678, 0x0001));

    // allow only one service instance and ANY_METHOD policy
    EXPECT_TRUE(its_security->is_client_allowed(&its_8000_8000, 0x1234, 0x5678, 0xFFFF));
    EXPECT_TRUE(its_security->is_client_allowed(&its_8000_8000, 0x1234, 0x5678, 0x0001));

    // check request service
    EXPECT_TRUE(its_security->is_client_allowed(&its_5000_5000, 0x1234, 0x5678, 0x00, true));
    EXPECT_FALSE(its_security->is_client_allowed(&its_6000_6000, 0x1234, 0x5678, 0x00, true));
    EXPECT_FALSE(its_security->is_client_allowed(&its_7000_7000, 0x1234, 0x5678, 0x00, true));
    EXPECT_TRUE(its_security->is_client_allowed(&its_7000_7000, 0x2222, 0x5678, 0x00, true));
    EXPECT_TRUE(its_security->is_client_allowed(&its_8000_8000, 0x1234, 0x5678, 0x00, true));

    EXPECT_TRUE(its_security->check_credentials(0x1277, &its_1000_1000));
    EXPECT_FALSE(its_security->check_credentials(0x1277, &its_1001_1001));
    EXPECT_TRUE(its_security->check_credentials(0x1278, &its_1000_1000));
    EXPECT_TRUE(its_security->check_credentials(0x1278, &its_9000_9000));

    // Security update / removal whitelist
    EXPECT_TRUE(its_security->is_policy_removal_allowed(1000));
    EXPECT_TRUE(its_security->is_policy_removal_allowed(1001));
    EXPECT_TRUE(its_security->is_policy_removal_allowed(1008));
    EXPECT_TRUE(its_security->is_policy_removal_allowed(2000));
    EXPECT_TRUE(its_security->is_policy_removal_allowed(3000));

    EXPECT_FALSE(its_security->is_policy_removal_allowed(2001));
    EXPECT_FALSE(its_security->is_policy_removal_allowed(3001));

    // create a valid policy object that is on whitelist and test is_policy_update_allowed method
    std::shared_ptr<vsomeip::policy> _policy(std::make_shared<vsomeip::policy>());
    uint32_t its_uid = 1000;
    uint32_t its_gid = 1000;

    // policy elements
    boost::icl::discrete_interval<uid_t> its_uids(its_uid, its_uid);
    boost::icl::interval_set<gid_t> its_gids;
    its_gids.insert(boost::icl::interval<gid_t>::closed(its_gid, its_gid));

    _policy->credentials_ += std::make_pair(its_uids, its_gids);
    _policy->allow_who_ = true;
    _policy->allow_what_ = true;

    vsomeip::service_t its_service(0x1234);

    boost::icl::discrete_interval<vsomeip::instance_t> its_instances(0x1, 0x2);
    boost::icl::interval_set<vsomeip::method_t> its_methods;
    its_methods.insert(boost::icl::interval<vsomeip::method_t>::closed(0x01, 0x2));
    boost::icl::interval_map<vsomeip::instance_t,
        boost::icl::interval_set<vsomeip::method_t> > its_instances_methods;
    its_instances_methods += std::make_pair(its_instances, its_methods);

    _policy->requests_ += std::make_pair(
            boost::icl::discrete_interval<vsomeip::service_t>(
                    its_service, its_service,
                    boost::icl::interval_bounds::closed()),
            its_instances_methods);
    EXPECT_TRUE(its_security->is_policy_update_allowed(1000, _policy));

    // test valid policy that holds a single service id which is whitelisted
    vsomeip::service_t its_second_service(0x7800);
    _policy->requests_ += std::make_pair(
            boost::icl::discrete_interval<vsomeip::service_t>(
                    its_second_service, its_second_service,
                    boost::icl::interval_bounds::closed()),
            its_instances_methods);
    EXPECT_TRUE(its_security->is_policy_update_allowed(1000, _policy));

    // test invalid UID which is not whitelisted
    EXPECT_FALSE(its_security->is_policy_update_allowed(2002, _policy));

    // test invalid policy that additionally holds a service id which is not whitelisted
    vsomeip::service_t its_third_service(0x8888);
    _policy->requests_ += std::make_pair(
            boost::icl::discrete_interval<vsomeip::service_t>(
                    its_third_service, its_third_service,
                    boost::icl::interval_bounds::closed()),
            its_instances_methods);
    EXPECT_FALSE(its_security->is_policy_update_allowed(1000, _policy));
#endif // !VSOMEIP_DISABLE_SECURITY

    // TCP connection setting:
    // max TCP connect time / max allowed number of aborted TCP endpoint restarts until forced restart
    EXPECT_EQ(its_configuration->get_max_tcp_connect_time(), 10000u);
    EXPECT_EQ(its_configuration->get_max_tcp_restart_aborts(), 15u);

    // 6. Service discovery
    bool enabled = its_configuration->is_sd_enabled();
    std::string protocol = its_configuration->get_sd_protocol();
    uint16_t port = its_configuration->get_sd_port();
    std::string multicast = its_configuration->get_sd_multicast();

    uint32_t initial_delay_min = its_configuration->get_sd_initial_delay_min();
    uint32_t initial_delay_max = its_configuration->get_sd_initial_delay_max();
    int32_t repetitions_base_delay = its_configuration->get_sd_repetitions_base_delay();
    uint8_t repetitions_max = its_configuration->get_sd_repetitions_max();
    vsomeip::ttl_t ttl = its_configuration->get_sd_ttl();
    int32_t cyclic_offer_delay = its_configuration->get_sd_cyclic_offer_delay();
    int32_t request_response_delay = its_configuration->get_sd_request_response_delay();

    EXPECT_TRUE(check<bool>(enabled, _expected_enabled, "SD ENABLED"));
    EXPECT_TRUE(check<std::string>(protocol, _expected_protocol, "SD PROTOCOL"));
    EXPECT_TRUE(check<std::string>(multicast, _expected_multicast, "SD MULTICAST"));
    EXPECT_TRUE(check<uint16_t>(port, _expected_port, "SD PORT"));

    EXPECT_TRUE(check<uint32_t>(initial_delay_min, _expected_initial_delay_min, "SD INITIAL DELAY MIN"));
    EXPECT_TRUE(check<uint32_t>(initial_delay_max, _expected_initial_delay_max, "SD INITIAL DELAY MAX"));
    EXPECT_TRUE(check<int32_t>(repetitions_base_delay, _expected_repetitions_base_delay, "SD REPETITION BASE DELAY"));
    EXPECT_TRUE(check<uint8_t>(repetitions_max,_expected_repetitions_max, "SD REPETITION MAX"));
    EXPECT_TRUE(check<vsomeip::ttl_t>(ttl, _expected_ttl, "SD TTL"));
    EXPECT_TRUE(check<int32_t>(cyclic_offer_delay, static_cast<int32_t>(_expected_cyclic_offer_delay), "SD CYCLIC OFFER DELAY"));
    EXPECT_TRUE(check<int32_t>(request_response_delay, static_cast<int32_t>(_expected_request_response_delay), "SD RESPONSE REQUEST DELAY"));
    EXPECT_EQ(1000u, its_configuration->get_sd_offer_debounce_time());

    ASSERT_TRUE(vsomeip::plugin_manager::get()->unload_plugin(vsomeip::plugin_type_e::CONFIGURATION_PLUGIN));
}

TEST(configuration_test, check_config_file) {
    // Check current configuration file format
    check_file(CONFIGURATION_FILE,
               EXPECTED_UNICAST_ADDRESS,
               EXPECTED_HAS_CONSOLE,
               EXPECTED_HAS_FILE,
               EXPECTED_HAS_DLT,
               EXPECTED_VERSION_LOGGING_ENABLED,
               EXPECTED_VERSION_LOGGING_INTERVAL,
               EXPECTED_APPLICATION_MAX_DISPATCHERS,
               EXPECTED_APPLICATION_MAX_DISPATCH_TIME,
               EXPECTED_APPLICATION_MAX_DETACHED_THREAD_WAIT_TIME,
               EXPECTED_APPLICATION_THREADS,
               EXPECTED_APPLICATION_REQUEST_DEBOUNCE_TIME,
               EXPECTED_LOGFILE,
               EXPECTED_LOGLEVEL,
               EXPECTED_UNICAST_ADDRESS_1234_0022,
               EXPECTED_RELIABLE_PORT_1234_0022,
               EXPECTED_UNRELIABLE_PORT_1234_0022,
               EXPECTED_UNICAST_ADDRESS_1234_0023,
               EXPECTED_RELIABLE_PORT_1234_0023,
               EXPECTED_UNRELIABLE_PORT_1234_0023,
               EXPECTED_UNICAST_ADDRESS_2277_0022,
               EXPECTED_RELIABLE_PORT_2277_0022,
               EXPECTED_UNRELIABLE_PORT_2277_0022,
               EXPECTED_UNICAST_ADDRESS_2266_0022,
               EXPECTED_RELIABLE_PORT_2266_0022,
               EXPECTED_UNRELIABLE_PORT_2266_0022,
               EXPECTED_UNICAST_ADDRESS_4466_0321,
               EXPECTED_RELIABLE_PORT_4466_0321,
               EXPECTED_UNRELIABLE_PORT_4466_0321,
               EXPECTED_SD_ENABLED,
               EXPECTED_SD_PROTOCOL,
               EXPECTED_SD_MULTICAST,
               EXPECTED_SD_PORT,
               EXPECTED_INITIAL_DELAY_MIN,
               EXPECTED_INITIAL_DELAY_MAX,
               EXPECTED_REPETITIONS_BASE_DELAY,
               EXPECTED_REPETITIONS_MAX,
               EXPECTED_TTL,
               EXPECTED_CYCLIC_OFFER_DELAY,
               EXPECTED_REQUEST_RESPONSE_DELAY);
}

TEST(configuration_test, check_deprecated_config_file) {
    // Check deprecated configuration file format
    check_file(DEPRECATED_CONFIGURATION_FILE,
               EXPECTED_UNICAST_ADDRESS,
               EXPECTED_HAS_CONSOLE,
               EXPECTED_HAS_FILE,
               EXPECTED_HAS_DLT,
               EXPECTED_VERSION_LOGGING_ENABLED,
               EXPECTED_VERSION_LOGGING_INTERVAL,
               EXPECTED_APPLICATION_MAX_DISPATCHERS,
               EXPECTED_APPLICATION_MAX_DISPATCH_TIME,
               EXPECTED_APPLICATION_MAX_DETACHED_THREAD_WAIT_TIME,
               EXPECTED_APPLICATION_THREADS,
               EXPECTED_APPLICATION_REQUEST_DEBOUNCE_TIME,
               EXPECTED_LOGFILE,
               EXPECTED_LOGLEVEL,
               EXPECTED_UNICAST_ADDRESS_1234_0022,
               EXPECTED_RELIABLE_PORT_1234_0022,
               EXPECTED_UNRELIABLE_PORT_1234_0022,
               EXPECTED_UNICAST_ADDRESS_1234_0023,
               EXPECTED_RELIABLE_PORT_1234_0023,
               EXPECTED_UNRELIABLE_PORT_1234_0023,
               EXPECTED_UNICAST_ADDRESS_2277_0022,
               EXPECTED_RELIABLE_PORT_2277_0022,
               EXPECTED_UNRELIABLE_PORT_2277_0022,
               EXPECTED_UNICAST_ADDRESS_2266_0022,
               EXPECTED_RELIABLE_PORT_2266_0022,
               EXPECTED_UNRELIABLE_PORT_2266_0022,
               EXPECTED_UNICAST_ADDRESS_4466_0321,
               EXPECTED_RELIABLE_PORT_4466_0321,
               EXPECTED_UNRELIABLE_PORT_4466_0321,
               EXPECTED_SD_ENABLED,
               EXPECTED_SD_PROTOCOL,
               EXPECTED_SD_MULTICAST,
               EXPECTED_SD_PORT,
               EXPECTED_DEPRECATED_INITIAL_DELAY_MIN,
               EXPECTED_DEPRECATED_INITIAL_DELAY_MAX,
               EXPECTED_DEPRECATED_REPETITIONS_BASE_DELAY,
               EXPECTED_DEPRECATED_REPETITIONS_MAX,
               EXPECTED_DEPRECATED_TTL,
               EXPECTED_CYCLIC_OFFER_DELAY,
               EXPECTED_DEPRECATED_REQUEST_RESPONSE_DELAY);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
