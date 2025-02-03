// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_E2E_PROFILE01_PROFILE01_HPP
#define VSOMEIP_V3_E2E_PROFILE01_PROFILE01_HPP

#include <cstdint>

#include <vsomeip/defines.hpp>

#include "../../../buffer/buffer.hpp"

namespace vsomeip_v3 {
namespace e2e {
namespace profile01 {

struct profile_config;

class profile_01 {
  public:
    static uint8_t compute_crc(const profile_config &_config, const e2e_buffer &_buffer);

    static bool is_buffer_length_valid(const profile_config &_config, const e2e_buffer &_buffer);
};

// [SWS_E2E_00200]
enum class p01_data_id_mode : uint8_t {E2E_P01_DATAID_BOTH, E2E_P01_DATAID_ALT, E2E_P01_DATAID_LOW, E2E_P01_DATAID_NIBBLE};

struct profile_config {
    profile_config() = delete;

    profile_config(uint16_t _crc_offset, uint16_t _data_id,
                   p01_data_id_mode _data_id_mode, uint16_t _data_length,
                   uint16_t _counter_offset, uint16_t _data_id_nibble_offset)

        : crc_offset_(_crc_offset), data_id_(_data_id),
          data_id_mode_(_data_id_mode), data_length_(_data_length),
          counter_offset_(_counter_offset),
          data_id_nibble_offset_(_data_id_nibble_offset),
          base_(VSOMEIP_FULL_HEADER_SIZE) {
    }
    profile_config(const profile_config &_config) = default;
    profile_config &operator=(const profile_config &_config) = default;

    // [SWS_E2E_00018]
    uint16_t crc_offset_;
    uint16_t data_id_;
    p01_data_id_mode data_id_mode_;
    uint16_t data_length_;
    uint16_t counter_offset_;
    uint16_t data_id_nibble_offset_;

    // SOME/IP base
    size_t base_;
};

} // namespace profile01
} // namespace e2e
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_E2E_PROFILE01_PROFILE01_HPP
