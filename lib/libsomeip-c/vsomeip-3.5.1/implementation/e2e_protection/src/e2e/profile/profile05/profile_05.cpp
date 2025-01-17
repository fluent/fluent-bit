// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../../../../include/crc/crc.hpp"
#include "../../../../include/e2e/profile/profile05/profile_05.hpp"

namespace vsomeip_v3 {
namespace e2e {
namespace profile05 {

uint16_t profile_05::compute_crc(const profile_config &_config, const e2e_buffer &_buffer) {

    static const int crcSize = sizeof(uint16_t);

    buffer_view its_before(_buffer, _config.offset_);
    uint16_t computed_crc = e2e_crc::calculate_profile_05(its_before);

    if ((_config.offset_ + crcSize) < _buffer.size()) {
        buffer_view its_after(_buffer, _config.offset_ + crcSize, _buffer.size());
        computed_crc = e2e_crc::calculate_profile_05(its_after, computed_crc);
    }

    uint8_t dataId[2];
    dataId[0] = (_config.data_id_ >> 0) & 0xFF;
    dataId[1] = (_config.data_id_ >> 8) & 0xFF;
    buffer_view dataIdView(dataId, sizeof(dataId));

    computed_crc = e2e_crc::calculate_profile_05(dataIdView, computed_crc);

    return computed_crc;
}

bool profile_05::is_buffer_length_valid(const profile_config &_config, const e2e_buffer &_buffer) {
    return ((_config.data_length_ / 8) + 1U <= _buffer.size());
}
} // namespace profile05
} // namespace e2e
} // namespace vsomeip_v3
