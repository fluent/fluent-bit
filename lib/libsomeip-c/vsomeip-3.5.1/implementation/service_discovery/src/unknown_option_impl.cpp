// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/unknown_option_impl.hpp"

#include "../../message/include/deserializer.hpp"

namespace vsomeip_v3 {
namespace sd {

bool sd::unknown_option_impl::deserialize(deserializer * _from)
{
    // Deserialize the header.
    if (!option_impl::deserialize(_from)) {
        return false;
    }
    payload_ = std::vector<uint8_t>(length_ - 1);

    // Deserialize the payload.
    return _from->deserialize(payload_);
}

const std::vector<uint8_t>& unknown_option_impl::get_payload() const
{
    return payload_;
}

} // namespace sd
} // namespace vsomeip_v3
