// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SD_DESERIALIZER_HPP
#define VSOMEIP_V3_SD_DESERIALIZER_HPP

#include "../../message/include/deserializer.hpp"

namespace vsomeip_v3 {
namespace sd {

class message_impl;

class deserializer
        : public vsomeip_v3::deserializer {
public:
    deserializer(std::uint32_t _shrink_buffer_threshold);
    deserializer(uint8_t *_data, std::size_t _length,
                 std::uint32_t _shrink_buffer_threshold);
    deserializer(const deserializer &_other);
    virtual ~deserializer();

    message_impl * deserialize_sd_message();
};

} // namespace sd
} // vsomeip_v3

#endif // VSOMEIP_V3_SD_DESERIALIZER_HPP
