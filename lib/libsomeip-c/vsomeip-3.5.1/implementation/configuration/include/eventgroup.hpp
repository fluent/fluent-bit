// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_CFG_EVENTGROUP_HPP
#define VSOMEIP_V3_CFG_EVENTGROUP_HPP

#include <memory>

#include <vsomeip/primitive_types.hpp>

namespace vsomeip_v3 {
namespace cfg {

struct event;

struct eventgroup {
    eventgroup_t id_;
    std::set<std::shared_ptr<event> > events_;
    std::string multicast_address_;
    uint16_t multicast_port_;
    uint8_t threshold_;
};

} // namespace cfg
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_CFG_EVENTGROUP_HPP
