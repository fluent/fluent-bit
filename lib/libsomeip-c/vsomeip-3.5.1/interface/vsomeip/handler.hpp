// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_HANDLER_HPP_
#define VSOMEIP_V3_HANDLER_HPP_

#include <functional>
#include <memory>
#include <tuple>

#include <vsomeip/deprecated.hpp>
#include <vsomeip/primitive_types.hpp>
#include <vsomeip/vsomeip_sec.h>

namespace vsomeip_v3 {

class message;

typedef std::function< void (state_type_e) > state_handler_t;
typedef std::function< void (const std::shared_ptr< message > &) > message_handler_t;
typedef std::function< void (service_t, instance_t, bool) > availability_handler_t;
typedef std::function< void (service_t, instance_t, availability_state_e) > availability_state_handler_t;
VSOMEIP_DEPRECATED_UID_GID typedef std::function< bool (client_t, uid_t, gid_t, bool) > subscription_handler_t;
VSOMEIP_DEPRECATED_UID_GID typedef std::function< bool (client_t, uid_t, gid_t, const std::string &, bool) > subscription_handler_ext_t;
typedef std::function< void (const uint16_t) > error_handler_t;
typedef std::function< void (const service_t, const instance_t, const eventgroup_t,
                             const event_t, const uint16_t) > subscription_status_handler_t;
VSOMEIP_DEPRECATED_UID_GID typedef std::function< void (client_t, uid_t, gid_t, bool,
            std::function< void (const bool) > )> async_subscription_handler_t;
VSOMEIP_DEPRECATED_UID_GID typedef std::function< void (client_t, uid_t, gid_t, const std::string &, bool,
            std::function< void (const bool) > )> async_subscription_handler_ext_t;

typedef std::function< void (const std::vector<std::pair<service_t, instance_t>> &_services) > offered_services_handler_t;
typedef std::function< void () > watchdog_handler_t;

/*
 * vsomeip_sec_client_t-aware subscription handlers
 */
using subscription_handler_sec_t       = std::function<bool(client_t, const vsomeip_sec_client_t*, const std::string&, bool)>;
using async_subscription_handler_sec_t = std::function<void(client_t, const vsomeip_sec_client_t*, const std::string&, bool, std::function<void(bool)>)>;

struct ip_address_t {
    union {
        ipv4_address_t v4_;
        ipv6_address_t v6_;
    } address_;
    bool is_v4_;

    bool operator<(const ip_address_t& _other) const {
        if (is_v4_ && _other.is_v4_) {
            return address_.v4_ < _other.address_.v4_;
        } else if (!is_v4_ && !_other.is_v4_) {
            return address_.v6_ < _other.address_.v6_;
        } else if (is_v4_ && !_other.is_v4_) {
            return true;
        } else {
            return false;
        }
    }

    bool operator==(const ip_address_t& _other) const {
        if (is_v4_ && _other.is_v4_) {
            return address_.v4_ == _other.address_.v4_;
        } else if (!is_v4_ && !_other.is_v4_) {
            return address_.v6_ == _other.address_.v6_;
        } else {
            return false;
        }
    }

    bool operator!=(const ip_address_t& _other) const {
        return !(*this == _other);
    }

};

struct remote_info_t {
    ip_address_t ip_;
    std::uint16_t first_;
    std::uint16_t last_;
    bool is_range_;
    bool is_reliable_;

    bool operator<(const remote_info_t& _other) const {
        return std::tie(ip_, first_, last_, is_range_, is_reliable_) <
                std::tie(_other.ip_, _other.first_, _other.last_,
                         _other.is_range_, _other.is_reliable_);
    }
};

struct message_acceptance_t {
    std::uint32_t remote_address_;
    std::uint16_t local_port_;
    bool is_local_;
    service_t service_;
    instance_t instance_;
};

typedef std::function<bool(const remote_info_t&)> sd_acceptance_handler_t;
typedef std::function<void(const ip_address_t&)> reboot_notification_handler_t;
typedef std::function<void()> routing_ready_handler_t;
typedef std::function<void(routing_state_e)> routing_state_handler_t;
typedef std::function<void(security_update_state_e)> security_update_handler_t;
typedef std::function<bool(const message_acceptance_t&)> message_acceptance_handler_t;

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_HANDLER_HPP_
