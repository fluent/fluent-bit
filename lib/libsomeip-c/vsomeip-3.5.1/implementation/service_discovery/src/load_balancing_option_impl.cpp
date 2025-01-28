// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/load_balancing_option_impl.hpp"
#include "../../message/include/deserializer.hpp"
#include "../../message/include/serializer.hpp"

namespace vsomeip_v3 {
namespace sd {

load_balancing_option_impl::load_balancing_option_impl() {
    length_ = 1 + 2 + 2;
    type_ = option_type_e::LOAD_BALANCING;
    priority_ = 0;
    weight_ = 0;
}

load_balancing_option_impl::~load_balancing_option_impl() {
}

bool
load_balancing_option_impl::equals(const option_impl &_other) const {
    bool is_equal(option_impl::equals(_other));

    if (is_equal) {
        const load_balancing_option_impl &its_other
            = dynamic_cast<const load_balancing_option_impl &>(_other);
        is_equal = (priority_ == its_other.priority_
            && weight_ == its_other.weight_);
    }

    return is_equal;
}

priority_t load_balancing_option_impl::get_priority() const {
    return priority_;
}

void load_balancing_option_impl::set_priority(priority_t _priority) {
    priority_ = _priority;
}

weight_t load_balancing_option_impl::get_weight() const {
    return weight_;
}

void load_balancing_option_impl::set_weight(weight_t _weight) {
    weight_ = _weight;
}

bool load_balancing_option_impl::serialize(vsomeip_v3::serializer *_to) const {
    bool is_successful = option_impl::serialize(_to);
    is_successful = is_successful
            && _to->serialize(static_cast<uint16_t>(priority_));
    is_successful = is_successful
            && _to->serialize(static_cast<uint16_t>(weight_));
    return is_successful;
}

bool load_balancing_option_impl::deserialize(vsomeip_v3::deserializer *_from) {
    bool is_successful = option_impl::deserialize(_from);

    uint16_t tmp_priority = 0;
    is_successful = is_successful && _from->deserialize(tmp_priority);
    priority_ = static_cast<priority_t>(tmp_priority);

    uint16_t tmp_weight = 0;
    is_successful = is_successful && _from->deserialize(tmp_weight);
    weight_ = static_cast<weight_t>(tmp_weight);

    return is_successful;
}

} // namespace sd
} // namespace vsomeip_v3
