// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_HANDLER_HPP
#define VSOMEIP_HANDLER_HPP

#include <functional>
#include <memory>

#include "../../compat/vsomeip/primitive_types.hpp"

namespace vsomeip {

class message;

typedef std::function< void (state_type_e) > state_handler_t;
typedef std::function< void (const std::shared_ptr< message > &) > message_handler_t;
typedef std::function< void (service_t, instance_t, bool) > availability_handler_t;
typedef std::function< bool (client_t, bool) > subscription_handler_t;
typedef std::function< void (const uint16_t) > error_handler_t;
typedef std::function< void (const service_t, const instance_t, const eventgroup_t,
                             const event_t, const uint16_t) > subscription_status_handler_t;
typedef std::function< void (client_t, bool, std::function< void (const bool) > )> async_subscription_handler_t;

typedef std::function< void (const std::vector<std::pair<service_t, instance_t>> &_services) > offered_services_handler_t;
typedef std::function< void () > watchdog_handler_t;

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
typedef std::function<bool(const ip_address_t&)> offer_acceptance_handler_t;
typedef std::function<void(const ip_address_t&)> reboot_notification_handler_t;
typedef std::function<void()> routing_ready_handler_t;
typedef std::function<void(routing_state_e)> routing_state_handler_t;
typedef std::function<void(security_update_state_e)> security_update_handler_t;

} // namespace vsomeip

#endif // VSOMEIP_HANDLER_HPP
