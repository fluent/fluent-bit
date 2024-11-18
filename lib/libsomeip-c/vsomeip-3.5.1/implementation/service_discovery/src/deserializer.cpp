// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/deserializer.hpp"
#include "../include/message_impl.hpp"

namespace vsomeip_v3 {
namespace sd {

deserializer::deserializer(std::uint32_t _shrink_buffer_threshold)
        : vsomeip_v3::deserializer(_shrink_buffer_threshold) {
}

deserializer::deserializer(uint8_t *_data, std::size_t _length,
                           std::uint32_t _shrink_buffer_threshold)
        : vsomeip_v3::deserializer(_data, _length, _shrink_buffer_threshold) {
}

deserializer::deserializer(const deserializer &_other)
        : vsomeip_v3::deserializer(_other) {
}

deserializer::~deserializer() {
}

message_impl * deserializer::deserialize_sd_message() {
    message_impl* deserialized_message = new message_impl;
    if (0 != deserialized_message) {
        if (false == deserialized_message->deserialize(this)) {
            delete deserialized_message;
            deserialized_message = 0;
        }
    }

    return deserialized_message;
}

} // namespace sd
} // namespace vsomeip_v3
