// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>
#include <algorithm>

#include <vsomeip/internal/logger.hpp>
#include "../../../../include/e2e/profile/profile_custom/checker.hpp"

namespace vsomeip_v3 {
namespace e2e {
namespace profile_custom {

void profile_custom_checker::check(const e2e_buffer &_buffer,
        instance_t _instance,
        e2e::profile_interface::check_status_t &_generic_check_status) {

    (void)_instance;

    std::lock_guard<std::mutex> lock(check_mutex_);
    _generic_check_status = e2e::profile_interface::generic_check_status::E2E_ERROR;

    if (profile_custom::is_buffer_length_valid(config_, _buffer)) {
        uint32_t received_crc(0);
        uint32_t calculated_crc(0);

        received_crc = read_crc(_buffer);
        calculated_crc = profile_custom::compute_crc(config_, _buffer);
        if (received_crc == calculated_crc) {
            _generic_check_status = e2e::profile_interface::generic_check_status::E2E_OK;
        } else {
            _generic_check_status = e2e::profile_interface::generic_check_status::E2E_WRONG_CRC;
            VSOMEIP_INFO << std::hex << "E2E protection: CRC32 does not match: calculated CRC: "
                    << (uint32_t) calculated_crc << " received CRC: " << (uint32_t) received_crc;
        }
    }
}

uint32_t profile_custom_checker::read_crc(const e2e_buffer &_buffer) const {
    return (static_cast<uint32_t>(_buffer[config_.crc_offset_ ]) << 24U) |
           (static_cast<uint32_t>(_buffer[config_.crc_offset_ + 1U]) << 16U) |
           (static_cast<uint32_t>(_buffer[config_.crc_offset_ + 2U]) << 8U) |
           static_cast<uint32_t>(_buffer[config_.crc_offset_ + 3U]);
}

} // namespace profile_custom
} // namespace e2e
} // namespace vsomeip_v3
