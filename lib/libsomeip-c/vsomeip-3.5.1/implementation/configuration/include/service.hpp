// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_CFG_SERVICE_HPP
#define VSOMEIP_V3_CFG_SERVICE_HPP

#include <memory>

#include <vsomeip/primitive_types.hpp>

namespace vsomeip_v3 {
namespace cfg {

struct event;
struct eventgroup;

struct service {
    service_t service_;
    instance_t instance_;

    std::string unicast_address_;

    uint16_t reliable_;
    uint16_t unreliable_;

    std::string multicast_address_;
    uint16_t multicast_port_;

    std::string protocol_;

    // [0] = debounce_time
    // [1] = retention_time
    typedef std::map<method_t, std::array<std::chrono::nanoseconds, 2>> npdu_time_configuration_t;
    npdu_time_configuration_t debounce_times_requests_;
    npdu_time_configuration_t debounce_times_responses_;

    std::map<event_t, std::shared_ptr<event> > events_;
    std::map<eventgroup_t, std::shared_ptr<eventgroup> > eventgroups_;

    // SOME/IP-TP
    std::map<method_t, std::pair<uint16_t, uint32_t> > tp_client_config_;
    std::map<method_t, std::pair<uint16_t, uint32_t> > tp_service_config_;
};

} // namespace cfg
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_CFG_SERVICE_HPP
