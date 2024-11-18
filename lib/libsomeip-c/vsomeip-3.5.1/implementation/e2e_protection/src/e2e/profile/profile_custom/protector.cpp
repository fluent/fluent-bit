// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../../../../include/e2e/profile/profile_custom/protector.hpp"

namespace vsomeip_v3 {
namespace e2e {
namespace profile_custom {

void protector::protect(e2e_buffer &_buffer, instance_t _instance) {

    (void)_instance;

    std::lock_guard<std::mutex> lock(protect_mutex_);

    if (profile_custom::is_buffer_length_valid(config_, _buffer)) {
        // compute the CRC over DataID and Data
        uint32_t computed_crc = profile_custom::compute_crc(config_, _buffer);
        // write CRC in Data
        write_crc(_buffer, computed_crc);
    }
}

void protector::write_crc(e2e_buffer &_buffer, uint32_t _computed_crc) {
    _buffer[config_.crc_offset_] = static_cast<uint8_t>(_computed_crc >> 24U);
    _buffer[config_.crc_offset_ + 1U] = static_cast<uint8_t>(_computed_crc >> 16U);
    _buffer[config_.crc_offset_ + 2U] = static_cast<uint8_t>(_computed_crc >> 8U);
    _buffer[config_.crc_offset_ + 3U] = static_cast<uint8_t>(_computed_crc);
}

} // namespace profile_custom
} // namespace e2e
} // namespace vsomeip_v3
