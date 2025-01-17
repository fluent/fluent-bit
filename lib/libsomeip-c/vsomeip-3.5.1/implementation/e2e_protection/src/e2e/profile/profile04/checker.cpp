// Copyright (C) 2020-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include <vsomeip/internal/logger.hpp>

#include "../../../../include/e2e/profile/profile04/checker.hpp"
#include "../../../../../utility/include/bithelper.hpp"

namespace vsomeip_v3 {
namespace e2e {
namespace profile04 {

// [SWS_E2E_00355]
void profile_04_checker::check(const e2e_buffer &_buffer, instance_t _instance,
        e2e::profile_interface::check_status_t &_generic_check_status) {

    std::lock_guard<std::mutex> lock(check_mutex_);
    _generic_check_status = e2e::profile_interface::generic_check_status::E2E_ERROR;

    if (_instance > VSOMEIP_E2E_PROFILE04_MAX_INSTANCE) {
        VSOMEIP_ERROR << "E2E Profile 4 can only be used for instances [1-255]";
        return;
    }

    /** @req [SWS_E2E_356] */
    if (verify_input(_buffer)) {
        /** @req [SWS_E2E_357] */
        uint16_t its_received_length;
        if (read_16(_buffer, its_received_length, 0)) {
            /** @req [SWS_E2E_358] */
            uint16_t its_received_counter;
            if (read_16(_buffer, its_received_counter, 2)) {
                /** @req [SWS_E2E_359] */
                uint32_t its_received_data_id;
                if (read_32(_buffer, its_received_data_id, 4)) {
                    /** @req [SWS_E2E_360] */
                    uint32_t its_received_crc;
                    if (read_32(_buffer, its_received_crc, 8)) {
                        uint32_t its_crc = profile_04::compute_crc(config_, _buffer);
                        /** @req [SWS_E2E_361] */
                        if (its_received_crc != its_crc) {
                            _generic_check_status = e2e::profile_interface::generic_check_status::E2E_WRONG_CRC;
                            VSOMEIP_ERROR << std::hex << "E2E P04 protection: CRC32 does not match: calculated CRC: "
                                    << its_crc << " received CRC: " << its_received_crc;
                        } else {
                            uint32_t its_data_id(uint32_t(_instance) << 24 | config_.data_id_);
                            if (its_received_data_id == its_data_id
                                    && static_cast<size_t>(its_received_length) == _buffer.size()
                                    && verify_counter(_instance, its_received_counter)) {
                                _generic_check_status = e2e::profile_interface::generic_check_status::E2E_OK;
                            }
                        }
                    }
                }
            }
        }
    }
}

bool
profile_04_checker::verify_input(const e2e_buffer &_buffer) const {

    auto its_length = _buffer.size();
    return (its_length >= config_.min_data_length_
            && its_length <= config_.max_data_length_);
}

bool
profile_04_checker::verify_counter(instance_t _instance, uint16_t _received_counter) {

    uint16_t its_delta(0);

    auto find_counter = counter_.find(_instance);
    if (find_counter != counter_.end()) {
        uint16_t its_counter = find_counter->second;
        if (its_counter < _received_counter)
            its_delta = uint16_t(_received_counter - its_counter);
        else
            its_delta = uint16_t(uint16_t(0xffff) - its_counter + _received_counter);
    } else {
        counter_[_instance] = _received_counter;
    }

    return (its_delta <= config_.max_delta_counter_);
}

bool
profile_04_checker::read_16(const e2e_buffer &_buffer,
        uint16_t &_data, size_t _index) const {

    _data = bithelper::read_uint16_be(&_buffer[config_.offset_ + _index]);
    return true;
}

bool
profile_04_checker::read_32(const e2e_buffer &_buffer,
        uint32_t &_data, size_t _index) const {

    _data = bithelper::read_uint32_be(&_buffer[config_.offset_ + _index]);
    return true;
}

} // namespace profile01
} // namespace e2e
} // namespace vsomeip_v3
