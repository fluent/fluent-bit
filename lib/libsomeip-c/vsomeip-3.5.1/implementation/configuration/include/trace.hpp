// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_CFG_TRACE_HPP_
#define VSOMEIP_V3_CFG_TRACE_HPP_

#include <string>
#include <vector>

#include <vsomeip/primitive_types.hpp>
#include <vsomeip/trace.hpp>
#include "../../tracing/include/enumeration_types.hpp"

namespace vsomeip_v3 {
namespace cfg {

struct trace_channel {
    trace_channel_t id_;
    std::string name_;
};

struct trace_filter {
    trace_filter()
        : ftype_(vsomeip_v3::trace::filter_type_e::POSITIVE),
          is_range_(false) {
    }

    std::vector<trace_channel_t> channels_;
    vsomeip_v3::trace::filter_type_e ftype_;
    bool is_range_;
    std::vector<vsomeip_v3::trace::match_t> matches_;
};

struct trace {
    trace()
        : is_enabled_(false),
          is_sd_enabled_(false),
          channels_(),
          filters_() {
    }

    bool is_enabled_;
    bool is_sd_enabled_;

    std::vector<std::shared_ptr<trace_channel>> channels_;
    std::vector<std::shared_ptr<trace_filter>> filters_;
};

} // namespace cfg
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_CFG_TRACE_HPP_
