// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include <vsomeip/internal/logger.hpp>
#include "../../../../include/e2e/profile/profile07/protector.hpp"
#include "../../../../../utility/include/bithelper.hpp"

namespace vsomeip_v3 {
namespace e2e {
namespace profile07 {

/** @req [SWS_E2E_00486] */
void
protector::protect(e2e_buffer &_buffer, instance_t _instance) {
    std::lock_guard<std::mutex> lock(protect_mutex_);

    /** @req: [SWS_E2E_00487] */
    if (verify_inputs(_buffer)) {

        /** @req [SWS_E2E_00489] */
        bithelper::write_uint32_be(static_cast<uint16_t>(_buffer.size()), &_buffer[config_.offset_ + PROFILE_07_SIZE_OFFSET]);

        /** @req [SWS_E2E_00490] */
        bithelper::write_uint32_be(get_counter(_instance), &_buffer[config_.offset_ + PROFILE_07_COUNTER_OFFSET]);

        /** @req [SWS_E2E_00491] */
        bithelper::write_uint32_be(config_.data_id_, &_buffer[config_.offset_ + PROFILE_07_DATAID_OFFSET]);

        /** @req [SWS_E2E_00492] */
        uint64_t its_crc = profile_07::compute_crc(config_, _buffer);

        /** @req [SWS_E2E_00493] */
        bithelper::write_uint64_be(its_crc, &_buffer[config_.offset_ + PROFILE_07_CRC_OFFSET]);

        /** @req [SWS_E2E_00494] */
        increment_counter(_instance);
    }
}

bool
protector::verify_inputs(e2e_buffer &_buffer) {

    return (_buffer.size() >= config_.min_data_length_
            && _buffer.size() <= config_.max_data_length_);
}

uint32_t
protector::get_counter(instance_t _instance) const {

    uint32_t its_counter(0);

    auto find_counter = counter_.find(_instance);
    if (find_counter != counter_.end())
        its_counter = find_counter->second;

    return its_counter;
}

void
protector::increment_counter(instance_t _instance) {

    auto find_counter = counter_.find(_instance);
    if (find_counter != counter_.end())
        find_counter->second++;
    else
        counter_[_instance] = 1;
}

} // namespace profile07
} // namespace e2e
} // namespace vsomeip_v3
