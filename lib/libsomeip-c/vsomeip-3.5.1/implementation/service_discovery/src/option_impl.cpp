// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/constants.hpp"
#include "../include/option_impl.hpp"
#include "../../message/include/deserializer.hpp"
#include "../../message/include/serializer.hpp"

namespace vsomeip_v3 {
namespace sd {

option_impl::option_impl() :
    length_(0),
    type_(option_type_e::UNKNOWN) {
}

option_impl::~option_impl() {
}

bool
option_impl::equals(const option_impl &_other) const {
   return (type_ == _other.get_type() && length_ == _other.get_length());
}

uint16_t option_impl::get_length() const {
    return length_;
}

option_type_e option_impl::get_type() const {
    return type_;
}

bool option_impl::serialize(vsomeip_v3::serializer *_to) const {
    return (0 != _to && _to->serialize(length_)
            && _to->serialize(static_cast<uint8_t>(type_))
            && _to->serialize(protocol::reserved_byte));
}

bool option_impl::deserialize(vsomeip_v3::deserializer *_from) {
    uint8_t its_type, reserved;
    bool l_result = (0 != _from && _from->deserialize(length_)
            && _from->deserialize(its_type) && _from->deserialize(reserved));

    if (l_result) {
        switch(static_cast<option_type_e>(its_type)) {
            case option_type_e::CONFIGURATION:
            case option_type_e::LOAD_BALANCING:
            case option_type_e::PROTECTION:
            case option_type_e::IP4_ENDPOINT:
            case option_type_e::IP6_ENDPOINT:
            case option_type_e::IP4_MULTICAST:
            case option_type_e::IP6_MULTICAST:
            case option_type_e::SELECTIVE:
                type_ = static_cast<option_type_e>(its_type);
                break;
            default:
                type_ = option_type_e::UNKNOWN;
        }
    }

    return l_result;
}

} // namespace sd
} // namespace vsomeip_v3
