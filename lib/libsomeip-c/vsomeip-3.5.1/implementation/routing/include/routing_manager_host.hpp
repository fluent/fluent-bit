// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_ROUTING_MANAGER_HOST_
#define VSOMEIP_V3_ROUTING_MANAGER_HOST_

#include <memory>

#include <boost/asio/io_context.hpp>
#include <vsomeip/error.hpp>
#include <vsomeip/vsomeip_sec.h>

namespace vsomeip_v3 {

class configuration;
class message;

class routing_manager_host {
public:
    virtual ~routing_manager_host() {
    }

    virtual client_t get_client() const = 0;
    virtual void set_client(const client_t &_client) = 0;
    virtual session_t get_session(bool _is_request) = 0;

    virtual const vsomeip_sec_client_t *get_sec_client() const = 0;
    virtual void set_sec_client_port(port_t _port) = 0;

    virtual const std::string & get_name() const = 0;
    virtual std::shared_ptr<configuration> get_configuration() const = 0;
    virtual boost::asio::io_context &get_io() = 0;

    virtual void on_availability(service_t _service, instance_t _instance,
            availability_state_e _state,
            major_version_t _major = DEFAULT_MAJOR,
            minor_version_t _minor = DEFAULT_MINOR) = 0;
    virtual void on_state(state_type_e _state) = 0;
    virtual void on_message(std::shared_ptr<message> &&_message) = 0;
    virtual void on_subscription(service_t _service, instance_t _instance,
        eventgroup_t _eventgroup,
        client_t _client, const vsomeip_sec_client_t *_sec_client,
        const std::string &_env, bool _subscribed,
        const std::function<void(bool)> &_accepted_cb) = 0;
    virtual void on_subscription_status(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, event_t _event, uint16_t _error) = 0;
    virtual void send(std::shared_ptr<message> _message) = 0;
    virtual void on_offered_services_info(
            std::vector<std::pair<service_t, instance_t>> &_services) = 0;
    virtual bool is_routing() const = 0;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_ROUTING_MANAGER_HOST_
