// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/endpoint_manager_impl.hpp"

#include <vsomeip/internal/logger.hpp>

#include "../include/local_tcp_server_endpoint_impl.hpp"
#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
#include "../include/local_uds_server_endpoint_impl.hpp"
#endif
#include "../include/udp_client_endpoint_impl.hpp"
#include "../include/udp_server_endpoint_impl.hpp"
#include "../include/tcp_client_endpoint_impl.hpp"
#include "../include/tcp_server_endpoint_impl.hpp"
#include "../include/virtual_server_endpoint_impl.hpp"
#include "../include/endpoint_definition.hpp"
#include "../../routing/include/routing_manager_base.hpp"
#include "../../routing/include/routing_manager_impl.hpp"
#include "../../routing/include/routing_host.hpp"
#include "../../utility/include/utility.hpp"
#include "../../utility/include/bithelper.hpp"


#include <forward_list>
#include <iomanip>

#ifndef WITHOUT_SYSTEMD
#include <systemd/sd-daemon.h>
#endif
#define SD_LISTEN_FDS_START 3

namespace vsomeip_v3 {

endpoint_manager_impl::endpoint_manager_impl(
        routing_manager_base* const _rm, boost::asio::io_context &_io,
        const std::shared_ptr<configuration>& _configuration) :
        endpoint_manager_base(_rm, _io, _configuration),
        is_processing_options_(true),
        options_thread_(std::bind(&endpoint_manager_impl::process_multicast_options, this)) {

    local_port_ = port_t(_configuration->get_routing_host_port() + 1);
    if (!is_local_routing_) {
        VSOMEIP_INFO << __func__ << ": Connecting to other clients from "
                << configuration_->get_routing_host_address().to_string()
                << ":" << std::dec << local_port_;
    }
}

endpoint_manager_impl::~endpoint_manager_impl() {

    {
        std::lock_guard<std::mutex> its_guard(options_mutex_);
        is_processing_options_ = false;
        options_condition_.notify_one();
    }
    options_thread_.join();
}

std::shared_ptr<endpoint> endpoint_manager_impl::find_or_create_remote_client(
        service_t _service, instance_t _instance, bool _reliable) {
    std::shared_ptr<endpoint> its_endpoint;
    bool start_endpoint(false);
    {
        std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
        its_endpoint = find_remote_client(_service, _instance, _reliable);
        if (!its_endpoint) {
            its_endpoint = create_remote_client(_service, _instance, _reliable);
            start_endpoint = true;
        }
    }
    if (start_endpoint && its_endpoint
            && configuration_->is_someip(_service, _instance)) {
        its_endpoint->start();
    }
    return its_endpoint;
}

void endpoint_manager_impl::find_or_create_remote_client(
        service_t _service, instance_t _instance) {
    std::shared_ptr<endpoint> its_reliable_endpoint;
    std::shared_ptr<endpoint> its_unreliable_endpoint;
    bool start_reliable_endpoint(false);
    bool start_unreliable_endpoint(false);
    {
        std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
        its_reliable_endpoint = find_remote_client(_service, _instance, true);
        if (!its_reliable_endpoint) {
            its_reliable_endpoint = create_remote_client(_service, _instance, true);
            start_reliable_endpoint = true;
        }
        its_unreliable_endpoint = find_remote_client(_service, _instance, false);
        if (!its_unreliable_endpoint) {
            its_unreliable_endpoint = create_remote_client(_service, _instance, false);
            start_unreliable_endpoint = true;
        }
    }
    const bool is_someip = configuration_->is_someip(_service, _instance);
    if (start_reliable_endpoint && its_reliable_endpoint && is_someip) {
        its_reliable_endpoint->start();
    }
    if (start_unreliable_endpoint && its_unreliable_endpoint && is_someip) {
        its_unreliable_endpoint->start();
    }
}

void endpoint_manager_impl::is_remote_service_known(
        service_t _service, instance_t _instance, major_version_t _major,
        minor_version_t _minor,
        const boost::asio::ip::address &_reliable_address,
        uint16_t _reliable_port, bool* _reliable_known,
        const boost::asio::ip::address &_unreliable_address,
        uint16_t _unreliable_port, bool* _unreliable_known) const {

    std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
    auto found_service = remote_service_info_.find(_service);
    if (found_service != remote_service_info_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            std::shared_ptr<endpoint_definition> its_definition;
            if (_reliable_port != ILLEGAL_PORT) {
                auto found_reliable = found_instance->second.find(true);
                if (found_reliable != found_instance->second.end()) {
                    its_definition = found_reliable->second;
                    if (its_definition->get_address() == _reliable_address
                            && its_definition->get_port() == _reliable_port) {
                        *_reliable_known = true;
                    } else {
                        VSOMEIP_WARNING << "Reliable service endpoint has changed: ["
                            << std::hex << std::setfill('0')
                            << std::setw(4) << _service << "."
                            << std::setw(4) << _instance << "."
                            << std::dec << static_cast<std::uint32_t>(_major) << "."
                            << _minor << "] old: "
                            << its_definition->get_address().to_string() << ":"
                            << its_definition->get_port() << " new: "
                            << _reliable_address.to_string() << ":"
                            << _reliable_port;
                    }
                }
            }
            if (_unreliable_port != ILLEGAL_PORT) {
                auto found_unreliable = found_instance->second.find(false);
                if (found_unreliable != found_instance->second.end()) {
                    its_definition = found_unreliable->second;
                    if (its_definition->get_address() == _unreliable_address
                            && its_definition->get_port() == _unreliable_port) {
                        *_unreliable_known = true;
                    } else {
                        VSOMEIP_WARNING << "Unreliable service endpoint has changed: ["
                            << std::hex << std::setfill('0')
                            << std::setw(4) << _service << "."
                            << std::setw(4) << _instance << "."
                            << std::dec << static_cast<std::uint32_t>(_major) << "."
                            << _minor << "] old: "
                            << its_definition->get_address().to_string() << ":"
                            << its_definition->get_port() << " new: "
                            << _unreliable_address.to_string() << ":"
                            << _unreliable_port;
                    }
                }
            }
        }
    }
}

void endpoint_manager_impl::add_remote_service_info(
        service_t _service, instance_t _instance,
        const std::shared_ptr<endpoint_definition>& _ep_definition) {

    std::shared_ptr<serviceinfo> its_info;
    std::shared_ptr<endpoint> its_endpoint;
    bool must_report(false);
    {
        std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
        remote_service_info_[_service][_instance][_ep_definition->is_reliable()] =
            _ep_definition;

        if (_ep_definition->is_reliable()) {
            its_endpoint = find_remote_client(_service, _instance, true);
            must_report = (its_endpoint && its_endpoint->is_established_or_connected());
            if (must_report)
                its_info = rm_->find_service(_service, _instance);
        }
    }

    if (must_report)
        static_cast<routing_manager_impl*>(rm_)->service_endpoint_connected(
                _service, _instance, its_info->get_major(), its_info->get_minor(),
                its_endpoint, false);
}

void endpoint_manager_impl::add_remote_service_info(
        service_t _service, instance_t _instance,
        const std::shared_ptr<endpoint_definition>& _ep_definition_reliable,
        const std::shared_ptr<endpoint_definition>& _ep_definition_unreliable) {

    std::shared_ptr<serviceinfo> its_info;
    std::shared_ptr<endpoint> its_reliable, its_unreliable;
    bool must_report(false);
    {
        std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
        remote_service_info_[_service][_instance][false] = _ep_definition_unreliable;
        remote_service_info_[_service][_instance][true] = _ep_definition_reliable;

        its_unreliable = find_remote_client(_service, _instance, false);
        its_reliable = find_remote_client(_service, _instance, true);

        must_report = (its_unreliable && its_unreliable->is_established_or_connected()
                && its_reliable && its_reliable->is_established_or_connected());

        if (must_report)
            its_info = rm_->find_service(_service, _instance);
    }

    if (must_report) {
        static_cast<routing_manager_impl*>(rm_)->service_endpoint_connected(
                _service, _instance, its_info->get_major(), its_info->get_minor(),
                its_unreliable, false);
        static_cast<routing_manager_impl*>(rm_)->service_endpoint_connected(
                _service, _instance, its_info->get_major(), its_info->get_minor(),
                its_reliable, false);
    }
}

void endpoint_manager_impl::clear_remote_service_info(service_t _service,
                                                      instance_t _instance,
                                                      bool _reliable) {
    std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
    const auto found_service = remote_service_info_.find(_service);
    if (found_service != remote_service_info_.end()) {
        const auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            if (found_instance->second.erase(_reliable)) {
                if (!found_instance->second.size()) {
                    found_service->second.erase(found_instance);
                    if (!found_service->second.size()) {
                        remote_service_info_.erase(found_service);
                    }
                }
            }
        }
    }
}

std::shared_ptr<endpoint>
endpoint_manager_impl::create_server_endpoint(uint16_t _port, bool _reliable, bool _start) {
    std::shared_ptr<endpoint> its_server_endpoint;
    boost::system::error_code its_error;
    boost::asio::ip::address its_unicast {configuration_->get_unicast_address()};
    const std::string its_unicast_str {its_unicast.to_string()};

    std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
    if (_start) {
        if (_reliable) {
            auto its_tmp {std::make_shared<tcp_server_endpoint_impl>(shared_from_this(),
                                  rm_->shared_from_this(), io_, configuration_)};
            if (its_tmp) {
                boost::asio::ip::tcp::endpoint its_reliable(its_unicast, _port);
                its_tmp->init(its_reliable, its_error);
                if (!its_error) {
                    if (configuration_->has_enabled_magic_cookies(
                            its_unicast_str, _port) ||
                            configuration_->has_enabled_magic_cookies(
                                    "local", _port)) {
                        its_tmp->enable_magic_cookies();
                    }
                    its_server_endpoint = its_tmp;
                }
            }
        } else {
            auto its_tmp {std::make_shared<udp_server_endpoint_impl>(shared_from_this(),
                                  rm_->shared_from_this(), io_, configuration_)};
            if (its_tmp) {
                boost::asio::ip::udp::endpoint its_unreliable(its_unicast, _port);
                its_tmp->init(its_unreliable, its_error);
                if (!its_error) {
                    its_server_endpoint = its_tmp;
                }
            }
        }
    } else {
        its_server_endpoint = std::make_shared<virtual_server_endpoint_impl>(its_unicast_str,
                                      _port, _reliable, io_);
    }

    if (its_server_endpoint) {
        server_endpoints_[_port][_reliable] = its_server_endpoint;
        its_server_endpoint->start();
    } else {
        VSOMEIP_ERROR << __func__
                << " Server endpoint creation failed."
                << " Reason: " << its_error.message()
                << " Port: " << _port
                << " (" << _reliable << ")";
    }

    return its_server_endpoint;
}

std::shared_ptr<endpoint> endpoint_manager_impl::find_server_endpoint(
        uint16_t _port, bool _reliable) const {
    std::shared_ptr<endpoint> its_endpoint;
    std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
    auto found_port = server_endpoints_.find(_port);
    if (found_port != server_endpoints_.end()) {
        auto found_endpoint = found_port->second.find(_reliable);
        if (found_endpoint != found_port->second.end()) {
            its_endpoint = found_endpoint->second;
        }
    }
    return its_endpoint;
}

std::shared_ptr<endpoint> endpoint_manager_impl::find_or_create_server_endpoint(
        uint16_t _port, bool _reliable, bool _start,  service_t _service,
        instance_t _instance, bool &_is_found, bool _is_multicast) {
    std::shared_ptr<endpoint> its_endpoint = find_server_endpoint(_port,
            _reliable);
    _is_found = false;
    if (!its_endpoint) {
        its_endpoint = create_server_endpoint(_port, _reliable, _start);
    } else {
        _is_found = true;
    }
    if (its_endpoint) {
        std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
        if (!_is_multicast) {
            service_instances_[_service][its_endpoint.get()] =  _instance;
        }
    }
    return its_endpoint;
}

bool endpoint_manager_impl::remove_server_endpoint(uint16_t _port, bool _reliable) {

    std::shared_ptr<endpoint> its_endpoint;
    {
        std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
        auto found_port = server_endpoints_.find(_port);
        if (found_port != server_endpoints_.end()) {
            auto found_reliable = found_port->second.find(_reliable);
            if (found_reliable != found_port->second.end()) {
                its_endpoint = found_reliable->second;
            }
        }
    }

    if (!is_used_endpoint(its_endpoint.get())) {
        std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
        auto found_port = server_endpoints_.find(_port);
        if (found_port != server_endpoints_.end()) {
            if (found_port->second.erase(_reliable)) {
                if (found_port->second.empty()) {
                    server_endpoints_.erase(found_port);
                }
            }
            return true;
        }
    }

    return false;
}

void
endpoint_manager_impl::clear_client_endpoints(
        service_t _service, instance_t _instance, bool _reliable) {

    std::shared_ptr<endpoint> its_endpoint;

    boost::asio::ip::address its_remote_address;
    port_t its_local_port(0);
    port_t its_remote_port(0);

    bool other_services_reachable_through_endpoint(false);

    {
        std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
        // Clear client endpoints for remote services (generic and specific ones)
        const auto found_service = remote_services_.find(_service);
        if (found_service != remote_services_.end()) {
            const auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                const auto found_reliability = found_instance->second.find(_reliable);
                if (found_reliability != found_instance->second.end()) {
                    service_instances_[_service].erase(found_reliability->second.get());
                    its_endpoint = found_reliability->second;
                    found_instance->second.erase(found_reliability);
                    if (found_instance->second.empty()) {
                        found_service->second.erase(found_instance);
                        if (found_service->second.empty()) {
                            remote_services_.erase(found_service);
                        }
                    }
                }
            }
        }

        // Only stop and delete the endpoint if none of the services
        // reachable through it is online anymore.
        if (its_endpoint) {
            for (const auto& service : remote_services_) {
                for (const auto& instance : service.second) {
                    const auto found_reliability = instance.second.find(_reliable);
                    if (found_reliability != instance.second.end()
                            && found_reliability->second == its_endpoint) {
                        other_services_reachable_through_endpoint = true;
                        break;
                    }
                }
                if (other_services_reachable_through_endpoint) { break; }
            }

            if (!other_services_reachable_through_endpoint) {
                partition_id_t its_partition;

                its_partition = configuration_->get_partition_id(_service, _instance);

                if (_reliable) {
                    std::shared_ptr<tcp_client_endpoint_impl> its_tcp_client_endpoint =
                            std::dynamic_pointer_cast<tcp_client_endpoint_impl>(its_endpoint);
                    if (its_tcp_client_endpoint) {
                        its_local_port = its_tcp_client_endpoint->get_local_port();
                        its_remote_port = its_tcp_client_endpoint->get_remote_port();
                        its_tcp_client_endpoint->get_remote_address(its_remote_address);
                    }
                } else {
                    std::shared_ptr<udp_client_endpoint_impl> its_udp_client_endpoint =
                            std::dynamic_pointer_cast<udp_client_endpoint_impl>(its_endpoint);
                    if (its_udp_client_endpoint) {
                        its_local_port = its_udp_client_endpoint->get_local_port();
                        its_remote_port = its_udp_client_endpoint->get_remote_port();
                        its_udp_client_endpoint->get_remote_address(its_remote_address);
                    }
                }
                const auto found_ip = client_endpoints_.find(its_remote_address);
                if (found_ip != client_endpoints_.end()) {
                    const auto found_port = found_ip->second.find(its_remote_port);
                    if (found_port != found_ip->second.end()) {
                        auto found_reliable = found_port->second.find(_reliable);
                        if (found_reliable != found_port->second.end()) {
                            const auto found_partition = found_reliable->second.find(its_partition);
                            if (found_partition != found_reliable->second.end()) {
                                if (found_partition->second == its_endpoint) {
                                    found_reliable->second.erase(its_partition);
                                    // delete if necessary
                                    if (0 == found_reliable->second.size()) {
                                        found_port->second.erase(_reliable);
                                        if (0 == found_port->second.size()) {
                                            found_ip->second.erase(found_port);
                                            if (0 == found_ip->second.size()) {
                                                client_endpoints_.erase(found_ip);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if (!other_services_reachable_through_endpoint && its_endpoint) {
        release_used_client_port(its_remote_address, its_remote_port,
                _reliable, its_local_port);

        its_endpoint->stop();
    }
}

void endpoint_manager_impl::find_or_create_multicast_endpoint(
        service_t _service, instance_t _instance,
        const boost::asio::ip::address &_sender,
        const boost::asio::ip::address &_address, uint16_t _port) {
    bool is_known_multicast(false);
    {
        std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
        const auto found_service = multicast_info_.find(_service);
        if (found_service != multicast_info_.end()) {
            const auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                const auto& endpoint_def = found_instance->second;
                if (endpoint_def->get_address() == _address &&
                        endpoint_def->get_port() == _port) {
                    // Multicast info and endpoint already created before
                    // This can happen when more than one client subscribe on the same instance!
                    is_known_multicast = true;
                }
            }
        }
    }
    const bool is_someip = configuration_->is_someip(_service, _instance);
    bool _is_found(false);
    // Create multicast endpoint & join multicase group
    std::shared_ptr<endpoint> its_endpoint = find_or_create_server_endpoint(
            _port, false, is_someip, _service, _instance, _is_found, true);
    if (!_is_found) {
        // Only save multicast info if we created a new endpoint
        // to be able to delete the new endpoint
        // as soon as the instance stops offering its service
        std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
        std::shared_ptr<endpoint_definition> endpoint_def =
                endpoint_definition::get(_address, _port, false, _service, _instance);
        multicast_info_[_service][_instance] = endpoint_def;
    }

    if (its_endpoint) {
        if (!is_known_multicast) {
            std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
            service_instances_multicast_[_service][_sender] = _instance;
        }

        auto its_udp_server_endpoint =
                std::dynamic_pointer_cast<udp_server_endpoint_impl>(its_endpoint);
        if (its_udp_server_endpoint)
            its_udp_server_endpoint->join(_address.to_string());
    } else {
        VSOMEIP_ERROR << "Could not find/create multicast endpoint!";
    }
}

void endpoint_manager_impl::clear_multicast_endpoints(service_t _service, instance_t _instance) {
    std::shared_ptr<endpoint> its_multicast_endpoint;
    std::string its_address;

    {
        std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
        // Clear multicast info and endpoint and multicast instance (remote service)
        if (multicast_info_.find(_service) != multicast_info_.end()) {
            if (multicast_info_[_service].find(_instance) != multicast_info_[_service].end()) {
                its_address = multicast_info_[_service][_instance]->get_address().to_string();
                uint16_t its_port = multicast_info_[_service][_instance]->get_port();
                auto found_port = server_endpoints_.find(its_port);
                if (found_port != server_endpoints_.end()) {
                    auto found_unreliable = found_port->second.find(false);
                    if (found_unreliable != found_port->second.end()) {
                        its_multicast_endpoint = found_unreliable->second;
                        server_endpoints_[its_port].erase(false);
                    }
                    if (found_port->second.find(true) == found_port->second.end()) {
                        server_endpoints_.erase(its_port);
                    }
                }
                multicast_info_[_service].erase(_instance);
                if (0 >= multicast_info_[_service].size()) {
                    multicast_info_.erase(_service);
                }
                (void)remove_instance_multicast(_service, _instance);
            }
        }
    }
    if (its_multicast_endpoint) {
        auto its_udp_server_endpoint =
                std::dynamic_pointer_cast<udp_server_endpoint_impl>(its_multicast_endpoint);
        if (its_udp_server_endpoint)
            its_udp_server_endpoint->leave(its_address);

        if (!is_used_endpoint(its_multicast_endpoint.get()))
            its_multicast_endpoint->stop();
    }
}

bool endpoint_manager_impl::supports_selective(service_t _service,
                                               instance_t _instance) const {
    bool supports_selective(false);
    std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
    const auto its_service = remote_service_info_.find(_service);
    if (its_service != remote_service_info_.end()) {
        const auto its_instance = its_service->second.find(_instance);
        if (its_instance != its_service->second.end()) {
            for (const auto& its_reliable : its_instance->second) {
                supports_selective |= configuration_->
                        supports_selective_broadcasts(
                                its_reliable.second->get_address());
            }
        }
    }
    return supports_selective;
}

void endpoint_manager_impl::print_status() const {
    // local client endpoints
    {
        std::map<client_t, std::shared_ptr<endpoint>> lces = get_local_endpoints();
        VSOMEIP_INFO << "status local client endpoints: " << std::dec << lces.size();
        for (const auto& lce : lces) {
            lce.second->print_status();
        }
    }

    // udp and tcp client endpoints
    {
        client_endpoints_t its_client_endpoints;
        server_endpoints_t its_server_endpoints;
        {
            std::scoped_lock its_lock {endpoint_mutex_};
            its_client_endpoints = client_endpoints_;
            its_server_endpoints = server_endpoints_;
        }
        VSOMEIP_INFO << "status start remote client endpoints:";
        std::uint32_t num_remote_client_endpoints(0);
        // normal endpoints
        for (const auto &its_address : its_client_endpoints) {
            for (const auto &its_port : its_address.second) {
                for (const auto &its_reliability : its_port.second) {
                    for (const auto &its_partition : its_reliability.second) {
                        its_partition.second->print_status();
                        num_remote_client_endpoints++;
                    }
                }
            }
        }
        VSOMEIP_INFO << "status end remote client endpoints: " << std::dec
                << num_remote_client_endpoints;

        VSOMEIP_INFO << "status start server endpoints:";
        std::uint32_t num_server_endpoints(1);
        // local server endpoints
        static_cast<routing_manager_impl*>(rm_)->print_stub_status();

        // server endpoints
        for (const auto& p : its_server_endpoints) {
            for (const auto& ru : p.second ) {
                ru.second->print_status();
                num_server_endpoints++;
            }
        }
        VSOMEIP_INFO << "status end server endpoints:"
                << std::dec << num_server_endpoints;
    }
}

bool endpoint_manager_impl::create_routing_root(std::shared_ptr<endpoint>& _root,
                                                bool& _is_socket_activated,
                                                const std::shared_ptr<routing_host>& _host) {

    std::stringstream its_endpoint_path_ss;
    its_endpoint_path_ss << utility::get_base_path(configuration_->get_network())
            << VSOMEIP_ROUTING_CLIENT;
    const std::string its_endpoint_path = its_endpoint_path_ss.str();
    client_t its_routing_host_id = configuration_->get_id(configuration_->get_routing_host_name());
    if (configuration_->is_security_enabled() && get_client() != its_routing_host_id) {
        VSOMEIP_ERROR << "endpoint_manager_impl::" << __func__ << ": "
                << "Client ["
                << std::hex << std::setw(4) << std::setfill('0')
                << get_client()
                << "] does not match the configured routing manager client identifier ["
                << std::hex << std::setw(4) << std::setfill('0')
                << its_routing_host_id
                << "]";

        return false;
    }

    if (configuration_->is_local_routing()) {
        int its_socket {0};
        int32_t num_fd {0};
#ifndef WITHOUT_SYSTEMD
        num_fd = sd_listen_fds(0);
#endif

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
        if (num_fd > 1) {
            VSOMEIP_ERROR <<  "Too many file descriptors received by systemd socket activation! num_fd: " << num_fd;
        } else if (num_fd == 1) {
            its_socket = SD_LISTEN_FDS_START + 0;
            VSOMEIP_INFO <<  "Using native socket created by systemd socket activation! fd: " << its_socket;
            if (is_local_routing_) {
                try {
                    auto its_root {std::make_shared <local_uds_server_endpoint_impl>(shared_from_this(),
                                           _host, io_, configuration_, true)};
                    if (its_root) {
                        boost::asio::local::stream_protocol::endpoint its_endpoint(its_endpoint_path);
                        boost::system::error_code its_error;

                        its_root->init(its_endpoint, its_socket, its_error);
                        if (its_error) {
                            VSOMEIP_ERROR << "Routing endpoint creation failed. Client ID: "
                                          << std::hex << std::setw(4) << std::setfill('0')
                                          << VSOMEIP_ROUTING_CLIENT << ": " << its_error.message();

                            its_root->deinit();
                            return false;
                        }

                        _root = its_root;
                    }
                } catch (const std::exception& e) {
                    VSOMEIP_ERROR << __func__ << ": " << e.what();
                }
            }
            _is_socket_activated = true;
        } else {
            if (is_local_routing_) {
                try {
                    if (-1 == ::unlink(its_endpoint_path.c_str()) && errno != ENOENT) {
                        VSOMEIP_ERROR << "endpoint_manager_impl::create_local_server unlink failed ("
                                << its_endpoint_path << "): "<< std::strerror(errno);
                    }
                    VSOMEIP_INFO << __func__ << ": Routing root @ " << its_endpoint_path;

                    auto its_root {std::make_shared <local_uds_server_endpoint_impl>(
                                            shared_from_this(), _host, io_, configuration_, true)};
                    if (its_root) {
                        boost::asio::local::stream_protocol::endpoint its_endpoint(its_endpoint_path);
                        boost::system::error_code its_error;

                        its_root->init(its_endpoint, its_error);
                        if (its_error) {
                            VSOMEIP_ERROR << "Local routing endpoint creation failed. Client ID: "
                                    << std::hex << std::setw(4) << std::setfill('0')
                                    << VSOMEIP_ROUTING_CLIENT << ": " << its_error.message();

                            its_root->deinit();
                            return false;
                        }

                        _root = its_root;
                    }
                } catch (const std::exception& e) {
                    VSOMEIP_ERROR << __func__ << ": " << e.what();
                }
            }
            _is_socket_activated = false;
        }
#else
        try {
            ::unlink(its_endpoint_path.c_str());
            port_t port = VSOMEIP_INTERNAL_BASE_PORT;
            VSOMEIP_INFO << __func__ << ": Routing root @ " << std::dec << port;

            auto its_root {std::make_shared <local_tcp_server_endpoint_impl>(shared_from_this(), _host,
                                     io_, configuration_, true)};
            if (its_root) {
                boost::asio::ip::tcp::endpoint its_endpoint(boost::asio::ip::tcp::v4(), port);
                boost::system::error_code its_error;

                its_root->init(its_endpoint, its_error);
                if (its_error) {
                    VSOMEIP_ERROR << "Local routing endpoint creation failed. Client ID: "
                                  << std::hex << std::setw(4) << std::setfill('0')
                                  << VSOMEIP_ROUTING_CLIENT << ": " << its_error.message();
                    its_root->deinit();
                    return false;
                }

                _root = its_root;
            }
        } catch (const std::exception& e) {
            VSOMEIP_ERROR << __func__ << ": " << e.what();
        }

        _is_socket_activated = false;
#endif // __linux__ || ANDROID
    } else {
        try {
            auto its_address = configuration_->get_routing_host_address();
            auto its_port = configuration_->get_routing_host_port();

            VSOMEIP_INFO << __func__ << ": Routing root @ "
                    << its_address.to_string() << ":" << std::dec << its_port;

            auto its_root {std::make_shared <local_tcp_server_endpoint_impl>(shared_from_this(), _host,
                                   io_, configuration_, true)};
            if (its_root) {
                boost::asio::ip::tcp::endpoint its_endpoint(its_address, its_port);
                boost::system::error_code its_error;

                int its_retry {0};
                do {
                    its_root->init(its_endpoint, its_error);
                    if (its_error) {
                        VSOMEIP_ERROR << "endpoint_manager_impl::create_routing_root: "
                            << "Remote routing root endpoint creation failed (" << its_retry << ") "
                            << "Client: " << std::hex << std::setw(4) << std::setfill('0')
                            << VSOMEIP_ROUTING_CLIENT << ": " << its_error.message();

                        its_root->deinit();
                        std::this_thread::sleep_for(
                            std::chrono::milliseconds(VSOMEIP_ROUTING_ROOT_RECONNECT_INTERVAL));
                    }
                    its_retry++;
                } while (its_retry < VSOMEIP_ROUTING_ROOT_RECONNECT_RETRIES && its_error);

                if (its_error) {
                    return false;
                }

                _root = its_root;
            }
        } catch (const std::exception& e) {
            VSOMEIP_ERROR << __func__ << ": " << e.what();
        }

        _is_socket_activated = false;
    }

    return true;
}

instance_t endpoint_manager_impl::find_instance(
        service_t _service, endpoint* const _endpoint) const {
    instance_t its_instance(0xFFFF);
    std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
    auto found_service = service_instances_.find(_service);
    if (found_service != service_instances_.end()) {
        auto found_endpoint = found_service->second.find(_endpoint);
        if (found_endpoint != found_service->second.end()) {
            its_instance = found_endpoint->second;
        }
    }
    return its_instance;
}

instance_t endpoint_manager_impl::find_instance_multicast(
        service_t _service, const boost::asio::ip::address &_sender) const {
    instance_t its_instance(0xFFFF);
    std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
    auto found_service = service_instances_multicast_.find(_service);
    if (found_service != service_instances_multicast_.end()) {
        auto found_sender = found_service->second.find(_sender);
        if (found_sender != found_service->second.end()) {
            its_instance = found_sender->second;
        }
    }
    return its_instance;
}

bool endpoint_manager_impl::remove_instance(service_t _service,
                                            endpoint* const _endpoint) {
    {
        std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
        auto found_service = service_instances_.find(_service);
        if (found_service != service_instances_.end()) {
            if (found_service->second.erase(_endpoint)) {
                if (!found_service->second.size()) {
                    service_instances_.erase(found_service);
                }
            }
        }
    }
    return !is_used_endpoint(_endpoint);
}

bool endpoint_manager_impl::remove_instance_multicast(service_t _service,
        instance_t _instance) {
    std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
    auto found_service = service_instances_multicast_.find(_service);
    if (found_service != service_instances_multicast_.end()) {
        for (auto &its_sender : found_service->second) {
            if (its_sender.second == _instance) {
                if (found_service->second.erase(its_sender.first)) {
                    if (!found_service->second.size()) {
                        service_instances_multicast_.erase(_service);
                    }
                }
                return true;
            }
        }
    }
    return false;
}

void endpoint_manager_impl::on_connect(std::shared_ptr<endpoint> _endpoint) {
    // Is called when endpoint->connect succeeded!
    struct service_info {
        service_t service_id_;
        instance_t instance_id_;
        major_version_t major_;
        minor_version_t minor_;
        std::shared_ptr<endpoint> endpoint_;
        bool service_is_unreliable_only_;
    };

    // Set to state CONNECTED as connection is not yet fully established in remote side POV
    // but endpoint is ready to send / receive. Set to ESTABLISHED after timer expires
    // to prevent inserting subscriptions twice or send out subscription before remote side
    // is finished with TCP 3 way handshake
    _endpoint->set_connected(true);

    std::forward_list<struct service_info> services_to_report_;
    {
        const bool endpoint_is_reliable = _endpoint->is_reliable();
        std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
        for (auto &its_service : remote_services_) {
            for (auto &its_instance : its_service.second) {
                auto found_endpoint = its_instance.second.find(endpoint_is_reliable);
                if (found_endpoint != its_instance.second.end()) {
                    if (found_endpoint->second == _endpoint) {
                        std::shared_ptr<serviceinfo> its_info(
                                rm_->find_service(its_service.first,
                                        its_instance.first));
                        if (!its_info) {
                            _endpoint->set_established(true);
                            return;
                        }
                        // only report services offered via TCP+UDP when both
                        // endpoints are connected
                        const auto its_other_endpoint = its_info->get_endpoint(
                                !endpoint_is_reliable);

                        if (!its_other_endpoint || (its_other_endpoint
                             && its_other_endpoint->is_established_or_connected())) {
                            services_to_report_.push_front(
                                        { its_service.first,
                                                its_instance.first,
                                                its_info->get_major(),
                                                its_info->get_minor(),
                                                _endpoint,
                                                (!endpoint_is_reliable &&
                                                        !its_other_endpoint)});
                        }
                    }
                }
            }
        }
    }
    for (const auto &s : services_to_report_) {
        static_cast<routing_manager_impl*>(rm_)->service_endpoint_connected(
                s.service_id_, s.instance_id_, s.major_, s.minor_, s.endpoint_,
                s.service_is_unreliable_only_);
    }
    if (services_to_report_.empty()) {
        _endpoint->set_established(true);
    }
}

void endpoint_manager_impl::on_disconnect(std::shared_ptr<endpoint> _endpoint) {
    // Is called when endpoint->connect fails!
    std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
    for (auto &its_service : remote_services_) {
        for (auto &its_instance : its_service.second) {
            const bool is_reliable = _endpoint->is_reliable();
            auto found_endpoint = its_instance.second.find(is_reliable);
            if (found_endpoint != its_instance.second.end()) {
                if (found_endpoint->second == _endpoint) {
                    std::shared_ptr<serviceinfo> its_info(
                            rm_->find_service(its_service.first,
                                    its_instance.first));
                    if(!its_info){
                        return;
                    }
                    if (!is_reliable) {
                        static_cast<routing_manager_impl*>(rm_)->on_availability(
                                its_service.first, its_instance.first,
                                availability_state_e::AS_UNAVAILABLE,
                                its_info->get_major(), its_info->get_minor());
                    }
                    static_cast<routing_manager_impl*>(rm_)->service_endpoint_disconnected(
                            its_service.first, its_instance.first,
                            its_info->get_major(),
                            its_info->get_minor(), _endpoint);
                }
            }
        }
    }
}

bool endpoint_manager_impl::on_bind_error(std::shared_ptr<endpoint> _endpoint,
        const boost::asio::ip::address &_remote_address, std::uint16_t _remote_port) {

    std::lock_guard<std::recursive_mutex> its_ep_lock(endpoint_mutex_);
    for (auto &its_service : remote_services_) {
        for (auto &its_instance : its_service.second) {
            const bool is_reliable = _endpoint->is_reliable();
            auto found_endpoint = its_instance.second.find(is_reliable);
            if (found_endpoint != its_instance.second.end()) {
                if (found_endpoint->second == _endpoint) {
                    // get a new client port using service / instance / remote port
                    uint16_t its_old_local_port = _endpoint->get_local_port();
                    uint16_t its_new_local_port(ILLEGAL_PORT);

                    std::unique_lock<std::mutex> its_lock(used_client_ports_mutex_);
                    std::map<bool, std::set<port_t> > its_used_client_ports;
                    get_used_client_ports(_remote_address, _remote_port, its_used_client_ports);
                    if (configuration_->get_client_port(
                            its_service.first, its_instance.first,
                            _remote_port, is_reliable,
                            its_used_client_ports, its_new_local_port)) {
                        _endpoint->set_local_port(its_new_local_port);
                        its_lock.unlock();
                        release_used_client_port(_remote_address, _remote_port,
                                _endpoint->is_reliable(), its_old_local_port);
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

void endpoint_manager_impl::on_error(
        const byte_t *_data, length_t _length, endpoint* const _receiver,
        const boost::asio::ip::address &_remote_address,
        std::uint16_t _remote_port) {
    instance_t its_instance = 0;
    if (_length >= VSOMEIP_SERVICE_POS_MAX) {
        service_t its_service = bithelper::read_uint16_be(&_data[VSOMEIP_SERVICE_POS_MIN]);
        its_instance = find_instance(its_service, _receiver);
    }
    static_cast<routing_manager_impl*>(rm_)->send_error(
            return_code_e::E_MALFORMED_MESSAGE, _data, _length, its_instance,
            _receiver->is_reliable(), _receiver, _remote_address, _remote_port);
}

void
endpoint_manager_impl::get_used_client_ports(
        const boost::asio::ip::address &_remote_address, port_t _remote_port,
        std::map<bool, std::set<port_t> > &_used_ports) {
    auto find_address = used_client_ports_.find(_remote_address);
    if (find_address != used_client_ports_.end()) {
        auto find_port = find_address->second.find(_remote_port);
        if (find_port != find_address->second.end())
            _used_ports = find_port->second;
    }
}

void
endpoint_manager_impl::request_used_client_port(
        const boost::asio::ip::address &_remote_address, port_t _remote_port,
        bool _reliable, port_t _local_port) {

    std::lock_guard<std::mutex> its_lock(used_client_ports_mutex_);
    used_client_ports_[_remote_address][_remote_port]
        [_reliable].insert(_local_port);
}

void
endpoint_manager_impl::release_used_client_port(
        const boost::asio::ip::address &_remote_address, port_t _remote_port,
        bool _reliable, port_t _local_port) {

    std::lock_guard<std::mutex> its_lock(used_client_ports_mutex_);
    auto find_address = used_client_ports_.find(_remote_address);
    if (find_address != used_client_ports_.end()) {
        auto find_port = find_address->second.find(_remote_port);
        if (find_port != find_address->second.end()) {
            auto find_reliable = find_port->second.find(_reliable);
            if (find_reliable != find_port->second.end())
                find_reliable->second.erase(_local_port);
        }
    }
}

std::shared_ptr<endpoint>
endpoint_manager_impl::find_remote_client(
        service_t _service, instance_t _instance, bool _reliable) {

    std::shared_ptr<endpoint> its_endpoint;
    auto found_service = remote_services_.find(_service);
    if (found_service != remote_services_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            auto found_reliability = found_instance->second.find(_reliable);
            if (found_reliability != found_instance->second.end()) {
                its_endpoint = found_reliability->second;
            }
        }
    }
    if (its_endpoint) {
        return its_endpoint;
    }

    // Endpoint did not yet exist. Get the partition id to check
    // whether the client endpoint for the partition does exist.
    partition_id_t its_partition_id
        = configuration_->get_partition_id(_service, _instance);

    // If another service within the same partition is hosted on the
    // same server_endpoint reuse the existing client_endpoint.
    auto found_service_info = remote_service_info_.find(_service);
    if (found_service_info != remote_service_info_.end()) {
        auto found_instance = found_service_info->second.find(_instance);
        if (found_instance != found_service_info->second.end()) {
            auto found_reliable = found_instance->second.find(_reliable);
            if (found_reliable != found_instance->second.end()) {
                std::shared_ptr<endpoint_definition> its_ep_def
                    = found_reliable->second;
                auto found_address = client_endpoints_.find(
                        its_ep_def->get_address());
                if (found_address != client_endpoints_.end()) {
                    auto found_port = found_address->second.find(
                            its_ep_def->get_remote_port());
                    if (found_port != found_address->second.end()) {
                        auto found_reliable2
                            = found_port->second.find(_reliable);
                        if (found_reliable2 != found_port->second.end()) {
                            auto found_partition
                                = found_reliable2->second.find(its_partition_id);
                            if (found_partition != found_reliable2->second.end()) {
                                its_endpoint = found_partition->second;

                                // store the endpoint under this service/instance id
                                // as well - needed for later cleanup
                                remote_services_[_service][_instance][_reliable]
                                    = its_endpoint;
                                service_instances_[_service][its_endpoint.get()] = _instance;

                                // add endpoint to serviceinfo object
                                auto found_service_info = rm_->find_service(_service,_instance);
                                if (found_service_info) {
                                    found_service_info->set_endpoint(its_endpoint, _reliable);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return its_endpoint;
}

std::shared_ptr<endpoint> endpoint_manager_impl::create_remote_client(
        service_t _service, instance_t _instance, bool _reliable) {
    std::shared_ptr<endpoint> its_endpoint;
    std::shared_ptr<endpoint_definition> its_endpoint_def;
    uint16_t its_local_port;

    boost::asio::ip::address its_remote_address;
    uint16_t its_remote_port = ILLEGAL_PORT;

    auto found_service = remote_service_info_.find(_service);
    if (found_service != remote_service_info_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            auto found_reliability = found_instance->second.find(_reliable);
            if (found_reliability != found_instance->second.end()) {
                its_endpoint_def = found_reliability->second;
                its_remote_address = its_endpoint_def->get_address();
                its_remote_port = its_endpoint_def->get_port();
            }
        }
    }

    if( its_remote_port != ILLEGAL_PORT) {
        // if client port range for remote service port range is configured
        // and remote port is in range, determine unused client port
        std::map<bool, std::set<port_t> > its_used_client_ports;
        {
            std::lock_guard<std::mutex> its_lock(used_client_ports_mutex_);
            get_used_client_ports(its_remote_address, its_remote_port, its_used_client_ports);
        }
        if (configuration_->get_client_port(_service, _instance,
                its_remote_port, _reliable,
                its_used_client_ports, its_local_port)) {
            if (its_endpoint_def) {
                its_endpoint = create_client_endpoint(
                        its_remote_address,
                        its_local_port,
                        its_remote_port,
                        _reliable);
            }

            if (its_endpoint) {
                request_used_client_port(its_remote_address, its_remote_port,
                        _reliable, its_local_port);

                service_instances_[_service][its_endpoint.get()] = _instance;
                remote_services_[_service][_instance][_reliable] = its_endpoint;

                partition_id_t its_partition
                    = configuration_->get_partition_id(_service, _instance);
                client_endpoints_[its_endpoint_def->get_address()]
                                 [its_endpoint_def->get_port()]
                                 [_reliable]
                                 [its_partition]= its_endpoint;
                // Set the basic route to the service in the service info
                auto found_service_info = rm_->find_service(_service, _instance);
                if (found_service_info) {
                    found_service_info->set_endpoint(its_endpoint, _reliable);
                }
                boost::system::error_code ec;
                VSOMEIP_INFO << "endpoint_manager_impl::create_remote_client: "
                        << its_endpoint_def->get_address().to_string(ec)
                        << ":" << std::dec << its_endpoint_def->get_port()
                        << " reliable: " << _reliable
                        << " using local port: " << std::dec << its_local_port;
            }
        }
    }
    return its_endpoint;
}

std::shared_ptr<endpoint> endpoint_manager_impl::create_client_endpoint(
        const boost::asio::ip::address &_address,
        uint16_t _local_port, uint16_t _remote_port,
        bool _reliable) {

    std::shared_ptr<endpoint> its_endpoint;
    boost::asio::ip::address its_unicast = configuration_->get_unicast_address();

    try {
        if (_reliable) {
            its_endpoint = std::make_shared<tcp_client_endpoint_impl>(
                    shared_from_this(),
                    rm_->shared_from_this(),
                    boost::asio::ip::tcp::endpoint(its_unicast, _local_port),
                    boost::asio::ip::tcp::endpoint(_address, _remote_port),
                    io_,
                    configuration_);

            if (configuration_->has_enabled_magic_cookies(_address.to_string(),
                    _remote_port)) {
                its_endpoint->enable_magic_cookies();
            }
        } else {
            its_endpoint = std::make_shared<udp_client_endpoint_impl>(
                    shared_from_this(),
                    rm_->shared_from_this(),
                    boost::asio::ip::udp::endpoint(its_unicast, _local_port),
                    boost::asio::ip::udp::endpoint(_address, _remote_port),
                    io_,
                    configuration_);
        }
    } catch (...) {
        VSOMEIP_ERROR << __func__ << " Client endpoint creation failed";
    }

    return its_endpoint;
}

void
endpoint_manager_impl::log_client_states() const {
    std::stringstream its_log;
    client_endpoints_t its_client_endpoints;
    std::vector<
        std::pair<
            std::tuple<boost::asio::ip::address, uint16_t, bool>,
            size_t
        >
    > its_client_queue_sizes;

    {
        std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
        its_client_endpoints = client_endpoints_;
    }

    for (const auto &its_address : its_client_endpoints) {
        for (const auto &its_port : its_address.second) {
            for (const auto &its_reliability : its_port.second) {
                for (const auto &its_partition : its_reliability.second) {
                    size_t its_queue_size = its_partition.second->get_queue_size();
                    if (its_queue_size > VSOMEIP_DEFAULT_QUEUE_WARN_SIZE)
                        its_client_queue_sizes.push_back(
                            std::make_pair(
                                std::make_tuple(
                                    its_address.first,
                                    its_port.first,
                                    its_reliability.first),
                                its_queue_size));
                }
            }
        }
    }

    std::sort(its_client_queue_sizes.begin(), its_client_queue_sizes.end(),
                [](const std::pair<
                        std::tuple<boost::asio::ip::address, uint16_t, bool>,
                        size_t> &_a,
                   const std::pair<
                       std::tuple<boost::asio::ip::address, uint16_t, bool>,
                       size_t> &_b) {
            return (_a.second > _b.second);
        });

    size_t its_max(std::min(size_t(5), its_client_queue_sizes.size()));
    for (size_t i = 0; i < its_max; i++) {
        its_log << std::hex << std::setw(4) << std::setfill('0')
                << std::get<0>(its_client_queue_sizes[i].first).to_string()
                << ":" << std::dec << std::get<1>(its_client_queue_sizes[i].first)
                << "(" << (std::get<2>(its_client_queue_sizes[i].first) ? "tcp" : "udp") << "):"
                << std::dec << its_client_queue_sizes[i].second;
        if (i < its_max-1)
            its_log << ", ";
    }

    if (its_log.str().length() > 0)
        VSOMEIP_INFO << "ECQ: [" << its_log.str() << "]";
}

void
endpoint_manager_impl::log_server_states() const {
    std::stringstream its_log;
    server_endpoints_t its_server_endpoints;
    std::vector<
        std::pair<
            std::pair<uint16_t, bool>,
            size_t
        >
    > its_client_queue_sizes;

    {
        std::scoped_lock its_lock {endpoint_mutex_};
        its_server_endpoints = server_endpoints_;
    }

    for (const auto &its_port : its_server_endpoints) {
        for (const auto &its_reliability : its_port.second) {
            size_t its_queue_size = its_reliability.second->get_queue_size();
            if (its_queue_size > VSOMEIP_DEFAULT_QUEUE_WARN_SIZE)
                its_client_queue_sizes.push_back(
                    std::make_pair(
                        std::make_pair(
                            its_port.first,
                            its_reliability.first),
                        its_queue_size));
        }
    }

    std::sort(its_client_queue_sizes.begin(), its_client_queue_sizes.end(),
                [](const std::pair<std::pair<uint16_t, bool>, size_t> &_a,
                   const std::pair<std::pair<uint16_t, bool>, size_t> &_b) {
            return (_a.second > _b.second);
        });

    size_t its_max(std::min(size_t(5), its_client_queue_sizes.size()));
    for (size_t i = 0; i < its_max; i++) {
        its_log << std::dec << its_client_queue_sizes[i].first.first
                << "(" << (its_client_queue_sizes[i].first.second ? "tcp" : "udp") << "):"
                << std::dec << its_client_queue_sizes[i].second;
        if (i < its_max-1)
            its_log << ", ";
    }

    if (its_log.str().length() > 0)
        VSOMEIP_INFO << "ESQ: [" << its_log.str() << "]";
}

void
endpoint_manager_impl::add_multicast_option(const multicast_option_t &_option) {

    std::lock_guard<std::mutex> its_guard(options_mutex_);
    options_queue_.push(_option);
    options_condition_.notify_one();
}

void
endpoint_manager_impl::process_multicast_options() {

    std::unique_lock<std::mutex> its_lock(options_mutex_);
    while (is_processing_options_) {
        if (options_queue_.size() > 0) {
            auto its_front = options_queue_.front();
            options_queue_.pop();
            auto its_udp_server_endpoint =
                    std::dynamic_pointer_cast<udp_server_endpoint_impl>(its_front.endpoint_);
            if (its_udp_server_endpoint) {
                // Unlock before setting the option as this might block
                its_lock.unlock();

                boost::system::error_code its_error;
                its_udp_server_endpoint->set_multicast_option(
                    its_front.address_, its_front.is_join_, its_error);

                if (its_error) {
                    VSOMEIP_ERROR << __func__ << ": "
                                  << (its_front.is_join_ ? "joining " : "leaving ")
                                  << its_front.address_ << " (" << its_error.message() << ")";
                }

                // Lock again after setting the option
                its_lock.lock();
            }
        } else {
            options_condition_.wait(its_lock);
        }
    }
}

bool endpoint_manager_impl::is_used_endpoint(endpoint* const _endpoint) const {

    {
        std::lock_guard<std::recursive_mutex> its_lock(endpoint_mutex_);
        // Do we still use the endpoint to offer a service instance?
        for (const auto& si : service_instances_)
            if (si.second.find(_endpoint) != si.second.end())
                return true;
    }

    // Do we still use the endpoint to join a multicast address=
    auto its_udp_server_endpoint = dynamic_cast<udp_server_endpoint_impl*>(_endpoint);
    if (its_udp_server_endpoint)
        return its_udp_server_endpoint->is_joining();

    return false;
}

void endpoint_manager_impl::suspend(void) {

    client_endpoints_t its_client_endpoints;
    server_endpoints_t its_server_endpoints;
    {
        // TODO: Check whether we can avoid copying
        std::scoped_lock its_lock {endpoint_mutex_};
        its_client_endpoints = client_endpoints_;
        its_server_endpoints = server_endpoints_;
    }

    // stop client endpoints
    for (auto& its_address : its_client_endpoints) {
        for (auto& its_port : its_address.second) {
            for (auto& its_protocol : its_port.second) {
                for (auto& its_partition : its_protocol.second) {
                    its_partition.second->stop();
                }
            }
        }
    }

    // start server endpoints
    for (auto& its_port : its_server_endpoints) {
        for (auto& its_protocol : its_port.second) {
            its_protocol.second->stop();
        }
    }
}

void endpoint_manager_impl::resume(void) {
    client_endpoints_t its_client_endpoints;
    server_endpoints_t its_server_endpoints;
    {
        // TODO: Check whether we can avoid copying
        std::scoped_lock its_lock {endpoint_mutex_};
        its_client_endpoints = client_endpoints_;
        its_server_endpoints = server_endpoints_;
    }

    // start server endpoints
    for (auto& its_port : its_server_endpoints) {
        for (auto& its_protocol : its_port.second) {
            its_protocol.second->restart();
        }
    }

    // start client endpoints
    for (auto& its_address : its_client_endpoints) {
        for (auto& its_port : its_address.second) {
            for (auto& its_protocol : its_port.second) {
                for (auto& its_partition : its_protocol.second) {
                    its_partition.second->restart();
                }
            }
        }
    }
}

} // namespace vsomeip_v3
