// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_ROUTING_TYPES_HPP_
#define VSOMEIP_V3_ROUTING_TYPES_HPP_

#include <map>
#include <memory>
#include <boost/asio/ip/address.hpp>

#include <vsomeip/primitive_types.hpp>
#include <vsomeip/constants.hpp>

namespace vsomeip_v3 {

class serviceinfo;
class endpoint_definition;


typedef std::map<service_t,
                 std::map<instance_t,
                          std::shared_ptr<serviceinfo> > > services_t;

class eventgroupinfo;

typedef std::map<service_t,
                 std::map<instance_t,
                          std::map<eventgroup_t,
                                   std::shared_ptr<
                                       eventgroupinfo> > > > eventgroups_t;

enum class registration_type_e : std::uint8_t {
    REGISTER = 0x1,
    DEREGISTER = 0x2,
    DEREGISTER_ON_ERROR = 0x3
};

enum class remote_subscription_state_e : std::uint8_t {
    SUBSCRIPTION_PENDING = 0x00,

    SUBSCRIPTION_ACKED   = 0x01,
    SUBSCRIPTION_NACKED  = 0x02,

    SUBSCRIPTION_ERROR   = 0x03,
    SUBSCRIPTION_UNKNOWN = 0xFF
};

typedef std::uint16_t remote_subscription_id_t;

struct msg_statistic_t {
    uint32_t counter_;
    length_t avg_length_;
};

}
// namespace vsomeip_v3

#endif // VSOMEIP_V3_ROUTING_TYPES_HPP_
