// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../../../../include/crc/crc.hpp"
#include "../../../../include/e2e/profile/profile04/profile_04.hpp"

namespace vsomeip_v3 {
namespace e2e {
namespace profile04 {

uint32_t profile_04::compute_crc(const profile_config &_config, const e2e_buffer &_buffer) {

    buffer_view its_before(_buffer, _config.offset_ + 8);
    uint32_t computed_crc = e2e_crc::calculate_profile_04(its_before);

    if (_config.offset_ + 12 < _buffer.size()) {
        buffer_view its_after(_buffer, _config.offset_ + 12, _buffer.size());
        computed_crc = e2e_crc::calculate_profile_04(its_after, computed_crc);
    }

    return computed_crc;
}

} // namespace profile04
} // namespace e2e
} // namespace vsomeip_v3
