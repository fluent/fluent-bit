// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_E2E_PROFILE_CUSTOM_PROFILE_CUSTOM_HPP
#define VSOMEIP_V3_E2E_PROFILE_CUSTOM_PROFILE_CUSTOM_HPP

#include <cstdint>

#include <vsomeip/defines.hpp>

#include "../../../buffer/buffer.hpp"

namespace vsomeip_v3 {
namespace e2e {
namespace profile_custom {

struct profile_config;

class profile_custom {
  public:
    static uint32_t compute_crc(const profile_config &_config, const e2e_buffer &_buffer);

    static bool is_buffer_length_valid(const profile_config &_config, const e2e_buffer &_buffer);
};

struct profile_config {
    profile_config() = delete;

    profile_config(uint16_t _crc_offset)
        : crc_offset_(_crc_offset),
          base_(VSOMEIP_FULL_HEADER_SIZE) {
    }
    profile_config(const profile_config &_config) = default;
    profile_config &operator=(const profile_config &_config) = default;

    uint16_t crc_offset_;
    size_t base_;
};

} // namespace profile_custom
} // namespace e2e
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_E2E_PROFILE_CUSTOM_PROFILE_CUSTOM_HPP
