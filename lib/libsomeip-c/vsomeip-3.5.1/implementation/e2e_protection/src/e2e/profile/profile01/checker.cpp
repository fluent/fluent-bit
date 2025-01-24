// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>
#include <algorithm>

#include <vsomeip/internal/logger.hpp>
#include "../../../../include/e2e/profile/profile01/checker.hpp"

namespace vsomeip_v3 {
namespace e2e {
namespace profile01 {

// [SWS_E2E_00196]
void profile_01_checker::check(const e2e_buffer &_buffer, instance_t _instance,
        e2e::profile_interface::check_status_t &_generic_check_status) {

    (void)_instance;

    std::lock_guard<std::mutex> lock(check_mutex_);
    _generic_check_status = e2e::profile_interface::generic_check_status::E2E_ERROR;

    if (profile_01::is_buffer_length_valid(config_, _buffer)) {
        uint8_t received_crc(0);
        uint8_t calculated_crc(0);
        received_crc = _buffer[config_.crc_offset_];
        calculated_crc = profile_01::compute_crc(config_, _buffer);
        if (received_crc == calculated_crc) {
            _generic_check_status = e2e::profile_interface::generic_check_status::E2E_OK;
        } else {
            _generic_check_status = e2e::profile_interface::generic_check_status::E2E_WRONG_CRC;
            VSOMEIP_INFO << std::hex << "E2E protection: CRC8 does not match: calculated CRC: "
                    << (uint32_t) calculated_crc << " received CRC: " << (uint32_t) received_crc;
        }
    }
}

} // namespace profile01
} // namespace e2e
} // namespace vsomeip_v3
