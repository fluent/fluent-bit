// Copyright (C) 2014-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/endpoint_manager_base.hpp"

#include <vsomeip/internal/logger.hpp>
#include "../include/local_tcp_client_endpoint_impl.hpp"
#include "../include/local_tcp_server_endpoint_impl.hpp"
#include "../../configuration/include/configuration.hpp"
#include "../../protocol/include/config_command.hpp"
#include "../../routing/include/routing_manager_base.hpp"
#include "../../utility/include/utility.hpp"

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
#include "../include/local_uds_client_endpoint_impl.hpp"
#include "../include/local_uds_server_endpoint_impl.hpp"
#endif

#include <iomanip>

namespace vsomeip_v3 {

endpoint_manager_base::endpoint_manager_base(
        routing_manager_base* const _rm,
        boost::asio::io_context &_io,
        const std::shared_ptr<configuration>& _configuration)
    : rm_(_rm),
      io_(_io),
      configuration_(_configuration),
      local_port_(ILLEGAL_PORT) {

    is_local_routing_ = configuration_->is_local_routing();
}

std::shared_ptr<endpoint> endpoint_manager_base::create_local(client_t _client) {
    std::lock_guard<std::mutex> its_lock(local_endpoint_mutex_);
    return create_local_unlocked(_client);
}

void endpoint_manager_base::remove_local(const client_t _client) {
    std::shared_ptr<endpoint> its_endpoint(find_local(_client));
    if (its_endpoint) {
        its_endpoint->register_error_handler(nullptr);
        its_endpoint->stop();
        VSOMEIP_INFO << "Client [" << std::hex << rm_->get_client() << "] is closing connection to ["
                      << std::hex << _client << "]" << " endpoint > " << its_endpoint;
        std::lock_guard<std::mutex> its_lock(local_endpoint_mutex_);
        local_endpoints_.erase(_client);
    }
}

std::shared_ptr<endpoint> endpoint_manager_base::find_or_create_local(client_t _client) {
    std::shared_ptr<endpoint> its_endpoint {nullptr};
    {
        std::scoped_lock its_lock {local_endpoint_mutex_};
        its_endpoint = find_local_unlocked(_client);
        if (!its_endpoint) {
            its_endpoint = create_local_unlocked(_client);
        }
    }
    if (its_endpoint) {
        its_endpoint->start();
    } else {
        VSOMEIP_ERROR << __func__ << ": couldn't find or create endpoint for client " << _client;
    }
    return its_endpoint;
}

std::shared_ptr<endpoint> endpoint_manager_base::find_local(client_t _client) {
    std::lock_guard<std::mutex> its_lock(local_endpoint_mutex_);
    return find_local_unlocked(_client);
}

std::shared_ptr<endpoint> endpoint_manager_base::find_local(service_t _service,
        instance_t _instance) {
    return find_local(rm_->find_local_client(_service, _instance));
}


std::unordered_set<client_t> endpoint_manager_base::get_connected_clients() const {
    std::lock_guard<std::mutex> its_lock(local_endpoint_mutex_);
    std::unordered_set<client_t> clients;
    for (const auto& its_client : local_endpoints_) {
        clients.insert(its_client.first);
    }
    return clients;
}

std::shared_ptr<endpoint> endpoint_manager_base::create_local_server(
        const std::shared_ptr<routing_host> &_routing_host) {
    std::shared_ptr<endpoint> its_local_server;
    std::stringstream its_path;
    its_path << utility::get_base_path(configuration_->get_network())
             << std::hex << rm_->get_client();
    const client_t its_client = rm_->get_client();

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
    if (is_local_routing_) {
        try {
            if (-1 == ::unlink(its_path.str().c_str()) && errno != ENOENT) {
                VSOMEIP_ERROR << "endpoint_manager_base::init_receiver unlink failed ("
                        << its_path.str() << "): "<< std::strerror(errno);
            }
            auto its_tmp {std::make_shared<local_uds_server_endpoint_impl>(
                                  shared_from_this(), _routing_host,
                                  io_, configuration_, false)};
            if (its_tmp) {
                boost::asio::local::stream_protocol::endpoint its_local_endpoint(its_path.str());
                boost::system::error_code its_error;
                its_tmp->init(its_local_endpoint, its_error);
                if (!its_error) {
                    VSOMEIP_INFO << __func__ << ": Listening @ " << its_path.str();
                    its_local_server = its_tmp;
                } else {
                    VSOMEIP_ERROR << "Local UDS server endpoint initialization failed. Client "
                                  << std::hex << std::setw(4) << std::setfill('0') << its_client
                                  << " Path: " << its_path.str() << " Reason: " << its_error.message();
                }
            } else {
                VSOMEIP_ERROR << "Local UDS server endpoint creation failed. Client "
                              << std::hex << std::setw(4) << std::setfill('0') << its_client
                              << " Path: " << its_path.str() << " Reason: out_of_memory";
            }
        } catch (const std::exception& e) {
            VSOMEIP_ERROR << __func__ << ": " << e.what();
        }
    } else {
#else
    {
#endif
        try {
            std::lock_guard<std::mutex> its_lock(create_local_server_endpoint_mutex_);
            ::unlink(its_path.str().c_str());
            port_t its_port;
            std::set<port_t> its_used_ports;
            auto its_address = configuration_->get_routing_guest_address();
            uint32_t its_current_wait_time { 0 };

            auto its_tmp {std::make_shared<local_tcp_server_endpoint_impl>(
                                  shared_from_this(), _routing_host, io_, configuration_, false)};
            if (its_tmp) {
                while (get_local_server_port(its_port, its_used_ports) && !its_local_server) {
                    boost::asio::ip::tcp::endpoint its_local_endpoint(its_address, its_port);
                    boost::system::error_code its_error;
                    its_tmp->init(its_local_endpoint, its_error);
                    if (!its_error) {
                        VSOMEIP_INFO << __func__ << ": Listening @ "
                                     << its_address.to_string() << ":" << std::dec << its_port;

                        if (rm_->is_routing_manager())
                            local_port_ = port_t(configuration_->get_routing_host_port() + 1);
                        else
                            local_port_ = port_t(its_port + 1);
                        VSOMEIP_INFO << __func__ << ": Connecting to other clients from "
                                << its_address.to_string() << ":" << std::dec << local_port_;

                        rm_->set_sec_client_port(local_port_);

                        its_local_server = its_tmp;
                    } else {
                        its_tmp->deinit();
                        if (its_error == boost::asio::error::address_in_use) {
                            its_used_ports.insert(its_port);
                        } else {
                            its_current_wait_time += LOCAL_TCP_PORT_WAIT_TIME;
                            if (its_current_wait_time > LOCAL_TCP_PORT_MAX_WAIT_TIME)
                                break;

                            std::this_thread::sleep_for(
                                    std::chrono::milliseconds(LOCAL_TCP_PORT_WAIT_TIME));
                        }
                    }
                }

                if (its_local_server) {
                    rm_->add_guest(its_client, its_address, its_port);
                } else {
                    VSOMEIP_ERROR << __func__ << ": Local TCP server endpoint initialization failed. "
                            << "Client " << std::hex << std::setw(4) << std::setfill('0') << its_client
                            << " Reason: No local port available!";
                }
            } else {
                VSOMEIP_ERROR << __func__ << ": Local TCP server endpoint creation failed. "
                        << "Client " << std::hex << std::setw(4) << std::setfill('0') << its_client
                        << " Reason: No local port available!";
            }
        } catch (const std::exception& e) {
            VSOMEIP_ERROR << __func__ << ": " << e.what();
        }
    }

    return its_local_server;
}

void endpoint_manager_base::on_connect(std::shared_ptr<endpoint> _endpoint) {
    rm_->on_connect(_endpoint);
}

void endpoint_manager_base::on_disconnect(std::shared_ptr<endpoint> _endpoint) {
    rm_->on_disconnect(_endpoint);
}

bool endpoint_manager_base::on_bind_error(std::shared_ptr<endpoint> _endpoint,
        const boost::asio::ip::address &_remote_address,
        uint16_t _remote_port) {

    (void)_endpoint;
    (void)_remote_address;
    (void)_remote_port;

    return true;
}

void endpoint_manager_base::on_error(
        const byte_t *_data, length_t _length, endpoint* const _receiver,
        const boost::asio::ip::address &_remote_address,
        std::uint16_t _remote_port) {

    (void)_data;
    (void)_length;
    (void)_receiver;
    (void)_remote_address;
    (void)_remote_port;
}

void endpoint_manager_base::release_port(uint16_t _port, bool _reliable) {
    (void)_port;
    (void)_reliable;
    // intentionally left blank
}

client_t endpoint_manager_base::get_client() const {
    return rm_->get_client();
}

std::string endpoint_manager_base::get_client_host() const {
    return rm_->get_client_host();
}

std::map<client_t, std::shared_ptr<endpoint>>
endpoint_manager_base::get_local_endpoints() const {
    std::lock_guard<std::mutex> its_lock(local_endpoint_mutex_);
    return local_endpoints_;
}

void
endpoint_manager_base::log_client_states() const {
    std::vector<std::pair<client_t, size_t> > its_client_queue_sizes;
    std::stringstream its_log;

    {
        std::lock_guard<std::mutex> its_lock(local_endpoint_mutex_);
        for (const auto &e : local_endpoints_) {
            size_t its_queue_size = e.second->get_queue_size();
            if (its_queue_size > VSOMEIP_DEFAULT_QUEUE_WARN_SIZE) {
                its_client_queue_sizes.push_back(
                        std::make_pair(e.first, its_queue_size));
            }
        }
    }

    std::sort(its_client_queue_sizes.begin(), its_client_queue_sizes.end(),
            [](const std::pair<client_t, size_t> &_a,
               const std::pair<client_t, size_t> &_b) {
        return (_a.second > _b.second);
    });

    size_t its_max(std::min(size_t(10), its_client_queue_sizes.size()));
    its_log << std::setfill('0');
    for (size_t i = 0; i < its_max; i++) {
        its_log << std::hex << std::setw(4) << its_client_queue_sizes[i].first << ":"
                << std::dec << its_client_queue_sizes[i].second;
        if (i < its_max-1)
            its_log << ", ";
    }

    if (its_log.str().length() > 0)
        VSOMEIP_WARNING << "ICQ: [" << its_log.str() << "]";
}

std::shared_ptr<endpoint>
endpoint_manager_base::create_local_unlocked(client_t _client) {

    std::stringstream its_path;
    its_path << utility::get_base_path(configuration_->get_network())
             << std::hex << _client;
    std::shared_ptr<endpoint> its_endpoint;

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
    if (is_local_routing_) {
        its_endpoint = std::make_shared<local_uds_client_endpoint_impl>(
            shared_from_this(), rm_->shared_from_this(),
            boost::asio::local::stream_protocol::endpoint(its_path.str()),
            io_, configuration_);
        VSOMEIP_INFO << "Client [" << std::hex << rm_->get_client() << "] is connecting to ["
            << std::hex << _client << "] at " << its_path.str() << " endpoint > " << its_endpoint;
    } else {
#else
    {
#endif
        boost::asio::ip::address its_local_address, its_remote_address;
        port_t its_remote_port;

        bool is_guest = rm_->get_guest(_client, its_remote_address, its_remote_port);
        if (is_guest) {
            try {
                its_local_address = configuration_->get_routing_guest_address();
                its_endpoint = std::make_shared<local_tcp_client_endpoint_impl>(
                        shared_from_this(), rm_->shared_from_this(),
                        boost::asio::ip::tcp::endpoint(its_local_address, local_port_),
                        boost::asio::ip::tcp::endpoint(its_remote_address, its_remote_port),
                        io_, configuration_);

                VSOMEIP_INFO << "Client ["
                        << std::hex << std::setw(4) << std::setfill('0') << rm_->get_client()
                        << "] @ "
                        << its_local_address.to_string() << ":" << std::dec << local_port_
                        << " is connecting to ["
                        << std::hex << std::setw(4) << std::setfill('0') << _client << "] @ "
                        << its_remote_address.to_string() << ":" << std::dec << its_remote_port
                        << " endpoint > " << its_endpoint;

            } catch (...) {
            }
        } else {
            VSOMEIP_ERROR << __func__
                    << ": Cannot get guest address of client ["
                    << std::hex << std::setw(4) << std::setfill('0')
                    << _client << "]";
        }
    }

    if (its_endpoint) {
        // Messages sent to the VSOMEIP_ROUTING_CLIENT are meant to be routed to
        // external devices. Therefore, its local endpoint must not be found by
        // a call to find_local. Thus it must not be inserted to the list of local
        // clients.
        if (_client != VSOMEIP_ROUTING_CLIENT) {
            local_endpoints_[_client] = its_endpoint;
        }
        rm_->register_client_error_handler(_client, its_endpoint);
    } else {
        VSOMEIP_WARNING << __func__ << ": (" << std::hex << get_client()
                        << ") not connected. Ignoring client assignment";
    }
    return its_endpoint;
}

std::shared_ptr<endpoint> endpoint_manager_base::find_local_unlocked(client_t _client) {
    std::shared_ptr<endpoint> its_endpoint;
    auto found_endpoint = local_endpoints_.find(_client);
    if (found_endpoint != local_endpoints_.end()) {
        its_endpoint = found_endpoint->second;
    }
    return its_endpoint;
}

instance_t endpoint_manager_base::find_instance(
        service_t _service, endpoint* const _endpoint) const {

    (void)_service;
    (void)_endpoint;

    return (0xFFFF);
}

bool
endpoint_manager_base::get_local_server_port(port_t &_port,
        const std::set<port_t> &_used_ports) const {

#define SERVER_PORT_OFFSET 2

#ifdef _WIN32
    uid_t its_uid { ANY_UID };
    gid_t its_gid { ANY_GID };
#else
    uid_t its_uid { getuid() };
    gid_t its_gid { getgid() };
#endif

    auto its_port_ranges = configuration_->get_routing_guest_ports(
            its_uid, its_gid);

    if (its_port_ranges.empty()) {
        VSOMEIP_WARNING << __func__ << ": No configured port ranges for uid/gid="
            << std::dec << its_uid << '/' << its_gid;
    }

    for (const auto &its_range : its_port_ranges) {
        for (int r = its_range.first; r < its_range.second;
                r += SERVER_PORT_OFFSET) {

            if (_used_ports.find(port_t(r)) == _used_ports.end()
                    && r != configuration_->get_routing_host_port()) {

                _port = port_t(r);
                return true;
            }
        }
    }

    return false;
}

void endpoint_manager_base::add_multicast_option(const multicast_option_t &_option) {
    (void)_option;
}

void endpoint_manager_base::suspend(void) {
    // Nothing to be done for internal endpoints
}
void endpoint_manager_base::resume(void) {
    // Nothing to be done for internal endpoints
}

} // namespace vsomeip_v3
