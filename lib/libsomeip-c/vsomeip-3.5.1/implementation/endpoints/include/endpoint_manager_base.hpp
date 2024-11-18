// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_ENDPOINT_MANAGER_BASE_HPP_
#define VSOMEIP_V3_ENDPOINT_MANAGER_BASE_HPP_

#include <mutex>
#include <map>
#include <set>
#include <unordered_set>
#include <memory>

#include <boost/asio/io_context.hpp>
#include <vsomeip/primitive_types.hpp>

#include "endpoint.hpp"
#include "endpoint_host.hpp"

namespace vsomeip_v3 {

class routing_manager_base;
class configuration;
class routing_host;

class endpoint_manager_base
        : public std::enable_shared_from_this<endpoint_manager_base>,
          public endpoint_host {
public:
    endpoint_manager_base(routing_manager_base* const _rm,
            boost::asio::io_context &_io,
            const std::shared_ptr<configuration>& _configuration);
    virtual ~endpoint_manager_base() = default;

    std::shared_ptr<endpoint> create_local(client_t _client);
    void remove_local(client_t _client);

    std::shared_ptr<endpoint> find_or_create_local(client_t _client);
    std::shared_ptr<endpoint> find_local(client_t _client);
    std::shared_ptr<endpoint> find_local(service_t _service, instance_t _instance);

    std::unordered_set<client_t> get_connected_clients() const;

    std::shared_ptr<endpoint> create_local_server(
            const std::shared_ptr<routing_host> &_routing_host);

    // endpoint_host interface
    virtual void on_connect(std::shared_ptr<endpoint> _endpoint);
    virtual void on_disconnect(std::shared_ptr<endpoint> _endpoint);
    virtual bool on_bind_error(std::shared_ptr<endpoint> _endpoint,
            const boost::asio::ip::address &_remote_address,
            uint16_t _remote_port);
    virtual void on_error(const byte_t *_data, length_t _length,
            endpoint* const _receiver,
            const boost::asio::ip::address &_remote_address,
            std::uint16_t _remote_port);
    virtual void release_port(uint16_t _port, bool _reliable);
    client_t get_client() const;
    std::string get_client_host() const;
    instance_t find_instance(service_t _service,
            endpoint* const _endpoint) const;

    // Statistics
    void log_client_states() const;

    // Multicast options
    void add_multicast_option(const multicast_option_t &_option);

    virtual void suspend(void);
    virtual void resume(void);

protected:
    std::map<client_t, std::shared_ptr<endpoint>> get_local_endpoints() const;

private:
    std::shared_ptr<endpoint> create_local_unlocked(client_t _client);
    std::shared_ptr<endpoint> find_local_unlocked(client_t _client);

    bool get_local_server_port(port_t &_port, const std::set<port_t> &_used_ports) const;

protected:
    routing_manager_base* const rm_;
    boost::asio::io_context &io_;
    std::shared_ptr<configuration> configuration_;

    bool is_local_routing_;
    port_t local_port_; // local (client) port when connecting to other
                        // vsomeip application via TCP

private:
    mutable std::mutex local_endpoint_mutex_;
    std::map<client_t, std::shared_ptr<endpoint> > local_endpoints_;

    mutable std::mutex create_local_server_endpoint_mutex_;

};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_ENDPOINT_MANAGER_BASE_HPP_
