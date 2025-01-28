// Copyright (C) 2020-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include <vsomeip/internal/logger.hpp>
#include "../../../../include/e2e/profile/profile05/protector.hpp"
#include "../../../../../utility/include/bithelper.hpp"

namespace vsomeip_v3 {
namespace e2e {
namespace profile05 {

void protector::protect(e2e_buffer &_buffer, instance_t _instance) {

    (void)_instance;

    std::lock_guard<std::mutex> lock(protect_mutex_);

    if (_instance > VSOMEIP_E2E_PROFILE05_MAX_INSTANCE) {
        VSOMEIP_ERROR << "E2E Profile 5 can only be used for instances [1-255]";
        return;
    }

    if (profile_05::is_buffer_length_valid(config_, _buffer)) {
        // write the current Counter value in Data
        write_counter(_buffer, get_counter(_instance), 2);

        // compute the CRC
        uint16_t its_crc = profile_05::compute_crc(config_, _buffer);
        bithelper::write_uint16_be(its_crc, &_buffer[config_.offset_]);

        // increment the Counter (new value will be used in the next invocation of E2E_P05Protect()),
        increment_counter(_instance);
    }
}

void
protector::write_counter(e2e_buffer &_buffer, uint8_t _data, size_t _index) {

    _buffer[config_.offset_ + _index] = _data;
}

uint8_t
protector::get_counter(instance_t _instance) const {

    uint8_t its_counter(0);

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

} // namespace profile05
} // namespace e2e
} // namespace vsomeip_v3
