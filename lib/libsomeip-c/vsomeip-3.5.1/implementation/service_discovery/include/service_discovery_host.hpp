// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SERVICE_DISCOVERY_HOST_HPP_
#define VSOMEIP_V3_SERVICE_DISCOVERY_HOST_HPP_

#include <map>
#include <memory>
#include <chrono>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/io_context.hpp>

#include "../../routing/include/function_types.hpp"
#include "../../routing/include/types.hpp"

#include <vsomeip/message.hpp>

namespace vsomeip_v3 {

class configuration;
class endpoint;
class endpoint_definition;

namespace sd {

class service_discovery_host {
public:
    virtual ~service_discovery_host() {
    }

    virtual boost::asio::io_context &get_io() = 0;

    virtual std::shared_ptr<endpoint> create_service_discovery_endpoint(
            const std::string &_address, uint16_t _port, bool _reliable) = 0;

    virtual services_t get_offered_services() const = 0;
    virtual std::shared_ptr<eventgroupinfo> find_eventgroup(service_t _service,
            instance_t _instance, eventgroup_t _eventgroup) const = 0;

    virtual bool send(client_t _client, std::shared_ptr<message> _message,
            bool _force) = 0;

    virtual bool send_via_sd(const std::shared_ptr<endpoint_definition> &_target,
            const byte_t *_data, uint32_t _size, uint16_t _sd_port) = 0;

    virtual void add_routing_info(service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor, ttl_t _ttl,
            const boost::asio::ip::address &_reliable_address,
            uint16_t _reliable_port,
            const boost::asio::ip::address &_unreliable_address,
            uint16_t _unreliable_port) = 0;

    virtual void del_routing_info(service_t _service, instance_t _instance,
            bool _has_reliable, bool _has_unreliable) = 0;

    virtual void update_routing_info(std::chrono::milliseconds _elapsed) = 0;

    virtual void on_remote_unsubscribe(
            std::shared_ptr<remote_subscription> &_subscription) = 0;

    virtual void on_subscribe_ack(client_t _client,
            service_t _service, instance_t _instance, eventgroup_t _eventgroup,
            event_t _event, remote_subscription_id_t _subscription_id) = 0;

    virtual void on_subscribe_ack_with_multicast(
            service_t _service, instance_t _instance,
            const boost::asio::ip::address &_sender,
            const boost::asio::ip::address &_address, uint16_t _port) = 0;

    virtual std::shared_ptr<endpoint> find_or_create_remote_client(
            service_t _service, instance_t _instance, bool _reliable) = 0;

    virtual void expire_subscriptions(const boost::asio::ip::address &_address) = 0;
    virtual void expire_subscriptions(const boost::asio::ip::address &_address,
                                      std::uint16_t _port, bool _reliable) = 0;
    virtual void expire_services(const boost::asio::ip::address &_address) = 0;
    virtual void expire_services(const boost::asio::ip::address &_address,
                                 std::uint16_t _port, bool _reliable) = 0;


    virtual void on_remote_subscribe(
            std::shared_ptr<remote_subscription> &_subscription,
            const remote_subscription_callback_t& _callback) = 0;

    virtual void on_subscribe_nack(client_t _client,
            service_t _service, instance_t _instance, eventgroup_t _eventgroup,
            bool _remove, remote_subscription_id_t _subscription_id) = 0;

    virtual std::chrono::steady_clock::time_point expire_subscriptions(bool _force) = 0;

    virtual std::shared_ptr<serviceinfo> get_offered_service(
            service_t _service, instance_t _instance) const = 0;
    virtual std::map<instance_t, std::shared_ptr<serviceinfo>> get_offered_service_instances(
            service_t _service) const = 0;

    virtual std::set<eventgroup_t> get_subscribed_eventgroups(service_t _service,
            instance_t _instance) = 0;
};

}  // namespace sd
}  // namespace vsomeip_v3

#endif // VSOMEIP_V3_SERVICE_DISCOVERY_HOST_HPP_

