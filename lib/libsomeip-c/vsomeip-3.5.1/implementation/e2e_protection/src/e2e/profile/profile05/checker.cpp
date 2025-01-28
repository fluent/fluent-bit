// Copyright (C) 2020-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include <vsomeip/internal/logger.hpp>

#include "../../../../include/e2e/profile/profile05/checker.hpp"
#include "../../../../../utility/include/bithelper.hpp"

namespace vsomeip_v3 {
namespace e2e {
namespace profile05 {

void profile_05_checker::check(const e2e_buffer &_buffer, instance_t _instance,
        e2e::profile_interface::check_status_t &_generic_check_status) {

    (void)_instance;

    std::lock_guard<std::mutex> lock(check_mutex_);
    _generic_check_status = e2e::profile_interface::generic_check_status::E2E_ERROR;

    if (_instance > VSOMEIP_E2E_PROFILE05_MAX_INSTANCE) {
        VSOMEIP_ERROR << "E2E Profile 5 can only be used for instances [1-255]";
        return;
    }

    if (profile_05::is_buffer_length_valid(config_, _buffer)) {
        uint8_t its_received_counter;
        if (read_8(_buffer, its_received_counter, 2)) {
            uint16_t its_received_crc;
            if (read_16(_buffer, its_received_crc, 0)) {
                uint16_t its_crc = profile_05::compute_crc(config_, _buffer);
                if (its_received_crc != its_crc) {
                    _generic_check_status = e2e::profile_interface::generic_check_status::E2E_WRONG_CRC;
                    VSOMEIP_ERROR << std::hex << "E2E P05 protection: CRC16 does not match: calculated CRC: "
                                  << its_crc << " received CRC: " << its_received_crc;
                } else {
                    if (verify_counter(_instance, its_received_counter)) {
                        _generic_check_status = e2e::profile_interface::generic_check_status::E2E_OK;
                    }
                }
            }
        }
    }
}

bool
profile_05_checker::verify_counter(instance_t _instance, uint8_t _received_counter) {

    uint8_t its_delta(0);

    auto find_counter = counter_.find(_instance);
    if (find_counter != counter_.end()) {
        uint8_t its_counter = find_counter->second;
        if (its_counter < _received_counter)
            its_delta = uint8_t(_received_counter - its_counter);
        else
            its_delta = uint8_t(uint8_t(0xff) - its_counter + _received_counter);
    } else {
        counter_[_instance] = _received_counter;
    }

    return (its_delta <= config_.max_delta_counter_);
}

bool
profile_05_checker::read_8(const e2e_buffer &_buffer,
        uint8_t &_data, size_t _index) const {

    _data = _buffer[config_.offset_ + _index];
    return true;
}

bool
profile_05_checker::read_16(const e2e_buffer &_buffer,
        uint16_t &_data, size_t _index) const {

    _data = bithelper::read_uint16_be(&_buffer[config_.offset_ + _index]);
    return true;
}

} // namespace profile01
} // namespace e2e
} // namespace vsomeip_v3
