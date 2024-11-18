// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/protection_option_impl.hpp"
#include "../../message/include/deserializer.hpp"
#include "../../message/include/serializer.hpp"

namespace vsomeip_v3 {
namespace sd {

protection_option_impl::protection_option_impl() {
    length_ = 1 + 4 + 4;
    type_ = option_type_e::PROTECTION;
    counter_ = 0;
    crc_ = 0;
}

protection_option_impl::~protection_option_impl() {
}

bool
protection_option_impl::equals(const option_impl &_other) const {
    bool is_equal(option_impl::equals(_other));

    if (is_equal) {
        const protection_option_impl &its_other
            = dynamic_cast<const protection_option_impl &>(_other);
        is_equal = (counter_ == its_other.counter_
                && crc_ == its_other.crc_);
    }

    return is_equal;
}

alive_counter_t protection_option_impl::get_alive_counter() const {
    return counter_;
}

void protection_option_impl::set_alive_counter(alive_counter_t _counter) {
    counter_ = _counter;
}

crc_t protection_option_impl::get_crc() const {
    return crc_;
}

void protection_option_impl::set_crc(crc_t _crc) {
    crc_ = _crc;
}

bool protection_option_impl::serialize(vsomeip_v3::serializer *_to) const {
    bool is_successful = option_impl::serialize(_to);
    is_successful = is_successful
            && _to->serialize(static_cast<uint32_t>(counter_));
    is_successful = is_successful
            && _to->serialize(static_cast<uint32_t>(crc_));
    return is_successful;
}

bool protection_option_impl::deserialize(vsomeip_v3::deserializer *_from) {
    bool is_successful = option_impl::deserialize(_from);

    uint32_t its_alive_counter = 0;
    is_successful = is_successful && _from->deserialize(its_alive_counter);
    counter_ = static_cast<alive_counter_t>(its_alive_counter);

    uint32_t its_crc = 0;
    is_successful = is_successful && _from->deserialize(its_crc);
    crc_ = static_cast<crc_t>(its_crc);

    return is_successful;
}

} // namespace sd
} // namespace vsomeip_v3
