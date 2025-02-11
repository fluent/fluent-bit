// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_CFG_EVENT_HPP
#define VSOMEIP_V3_CFG_EVENT_HPP

#include <memory>
#include <vector>

#include <vsomeip/primitive_types.hpp>

namespace vsomeip_v3 {
namespace cfg {

struct eventgroup;

struct event {
    event(event_t _id, bool _is_field, reliability_type_e _reliability,
            std::chrono::milliseconds _cycle, bool _change_resets_cycle,
            bool _update_on_change)
        : id_(_id),
          is_field_(_is_field),
          reliability_(_reliability),
          cycle_(_cycle),
          change_resets_cycle_(_change_resets_cycle),
          update_on_change_(_update_on_change) {
    }

    event_t id_;
    bool is_field_;
    reliability_type_e reliability_;
    std::vector<std::weak_ptr<eventgroup> > groups_;

    std::chrono::milliseconds cycle_;
    bool change_resets_cycle_;
    bool update_on_change_;
};

} // namespace cfg
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_CFG_EVENT_HPP
