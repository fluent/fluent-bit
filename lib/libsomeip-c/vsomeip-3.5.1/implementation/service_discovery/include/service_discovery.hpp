// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SD_SERVICE_DISCOVERY_HPP_
#define VSOMEIP_V3_SD_SERVICE_DISCOVERY_HPP_

#include <boost/asio/ip/address.hpp>

#include <vsomeip/primitive_types.hpp>
#include <vsomeip/enumeration_types.hpp>
#include <vsomeip/handler.hpp>
#include "../../routing/include/serviceinfo.hpp"
#include "../../endpoints/include/endpoint.hpp"
#include "../include/service_discovery_host.hpp"

namespace vsomeip_v3 {

class configuration;
class eventgroupinfo;

namespace sd {

class service_discovery {
public:
    virtual ~service_discovery() {
    }

    virtual boost::asio::io_context &get_io() = 0;

    virtual void init() = 0;
    virtual void start() = 0;
    virtual void stop() = 0;

    virtual void request_service(service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor, ttl_t _ttl) = 0;
    virtual void release_service(service_t _service, instance_t _instance) = 0;

    virtual void subscribe(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, major_version_t _major,
            ttl_t _ttl, client_t _client,
            const std::shared_ptr<eventgroupinfo>& _info) = 0;
    virtual void unsubscribe(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, client_t _client) = 0;
    virtual void unsubscribe_all(service_t _service, instance_t _instance) = 0;
    virtual void unsubscribe_all_on_suspend() = 0;

    virtual bool send(bool _is_announcing) = 0;

    virtual void on_message(const byte_t *_data, length_t _length,
            const boost::asio::ip::address &_sender,
            bool _is_multicast) = 0;

    virtual void
    sent_messages(const byte_t* _data, length_t _size,
                  const boost::asio::ip::address& _remote_address = boost::asio::ip::address()) = 0;

    virtual void on_endpoint_connected(
            service_t _service, instance_t _instance,
            const std::shared_ptr<endpoint> &_endpoint) = 0;

    virtual void offer_service(const std::shared_ptr<serviceinfo> &_info) = 0;
    virtual bool stop_offer_service(const std::shared_ptr<serviceinfo> &_info, bool _send) = 0;
    virtual bool send_collected_stop_offers(const std::vector<std::shared_ptr<serviceinfo>> &_infos) = 0;

    virtual void set_diagnosis_mode(const bool _activate) = 0;

    virtual bool get_diagnosis_mode() = 0;

    virtual void update_remote_subscription(
            const std::shared_ptr<remote_subscription> &_subscription) = 0;

    virtual void register_sd_acceptance_handler(
            const sd_acceptance_handler_t &_handler) = 0;
    virtual void register_reboot_notification_handler(
            const reboot_notification_handler_t &_handler) = 0;
    virtual std::recursive_mutex& get_subscribed_mutex() = 0;
};

} // namespace sd
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SD_SERVICE_DISCOVERY_HPP_
