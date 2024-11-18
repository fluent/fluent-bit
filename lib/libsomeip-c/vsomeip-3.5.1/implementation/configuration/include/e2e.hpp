// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_CFG_E2E_HPP_
#define VSOMEIP_V3_CFG_E2E_HPP_

#include <map>
#include <string>
#include <vector>

#include <vsomeip/primitive_types.hpp>

namespace vsomeip_v3 {
namespace cfg {

struct e2e {
    typedef std::map<std::string, std::string> custom_parameters_t;

    e2e() :
        variant(""),
        profile(""),
        service_id(0),
        event_id(0) {
    }

    e2e(const std::string &_variant, const std::string &_profile, service_t _service_id,
        event_t _event_id, custom_parameters_t&& _custom_parameters) :
        variant(_variant),
        profile(_profile),
        service_id(_service_id),
        event_id(_event_id),
        custom_parameters(_custom_parameters) {
    }

    // common config
    std::string variant;
    std::string profile;
    service_t service_id;
    event_t event_id;

    // custom parameters
    custom_parameters_t custom_parameters;
};

} // namespace cfg
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_CFG_E2E_HPP_
