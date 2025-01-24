// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include <vsomeip/internal/logger.hpp>

#include "../../../../include/e2e/profile/profile07/checker.hpp"
#include "../../../../../utility/include/bithelper.hpp"

namespace vsomeip_v3 {
namespace e2e {
namespace profile07 {

// [SWS_E2E_00495]
void profile_07_checker::check(const e2e_buffer &_buffer, instance_t _instance,
        e2e::profile_interface::check_status_t &_generic_check_status) {

    std::lock_guard<std::mutex> lock(check_mutex_);
    _generic_check_status = e2e::profile_interface::generic_check_status::E2E_ERROR;

    /** @req [SWS_E2E_00496] */
    if (verify_input(_buffer)) {
        /** @req [SWS_E2E_00497] */
        uint32_t its_received_length;
        if (read_32(_buffer, its_received_length, PROFILE_07_SIZE_OFFSET)) {
            /** @req [SWS_E2E_00498] */
            uint32_t its_received_counter;
            if (read_32(_buffer, its_received_counter, PROFILE_07_COUNTER_OFFSET)) {
                /** @req [SWS_E2E_00499] */
                uint32_t its_received_data_id;
                if (read_32(_buffer, its_received_data_id, PROFILE_07_DATAID_OFFSET)) {
                    /** @req [SWS_E2E_00500] */
                    uint64_t its_received_crc;
                    if (read_64(_buffer, its_received_crc, PROFILE_07_CRC_OFFSET)) {
                        uint64_t its_crc = profile_07::compute_crc(config_, _buffer);
                        /** @req [SWS_E2E_00501] */
                        if (its_received_crc != its_crc) {
                            _generic_check_status = e2e::profile_interface::generic_check_status::E2E_WRONG_CRC;
                            VSOMEIP_ERROR << std::hex << "E2E P07 protection: CRC32 does not match: calculated CRC: "
                                    << its_crc << " received CRC: " << its_received_crc;
                        } else {
                            if (its_received_data_id == config_.data_id_
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
profile_07_checker::verify_input(const e2e_buffer &_buffer) const {

    auto its_length = _buffer.size();
    return (its_length >= config_.min_data_length_
            && its_length <= config_.max_data_length_);
}

bool
profile_07_checker::verify_counter(instance_t _instance, uint32_t _received_counter) {

    uint32_t its_delta(0);

    auto find_counter = counter_.find(_instance);
    if (find_counter != counter_.end()) {
        uint32_t its_counter = find_counter->second;
        if (its_counter < _received_counter)
            its_delta = uint32_t(_received_counter - its_counter);
        else
            its_delta = uint32_t(uint32_t(0xffffffff) - its_counter + _received_counter);
    } else {
        counter_[_instance] = _received_counter;
    }

    return (its_delta <= config_.max_delta_counter_);
}

// Read uint32_t as big-endian
bool
profile_07_checker::read_32(const e2e_buffer &_buffer,
        uint32_t &_data, size_t _index) const {

    _data = bithelper::read_uint32_be(&_buffer[config_.offset_ + _index]);
    return true;
}

// Read uint64_t as big-endian
bool
profile_07_checker::read_64(const e2e_buffer &_buffer,
        uint64_t &_data, size_t _index) const {

    _data = bithelper::read_uint64_be(&_buffer[config_.offset_ + _index]);
    return true;
}


} // namespace profile01
} // namespace e2e
} // namespace vsomeip_v3
