// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_E2E_CRC_HPP
#define VSOMEIP_V3_E2E_CRC_HPP

#include <cstdint>
#include "../buffer/buffer.hpp"

namespace vsomeip_v3 {

class e2e_crc {
  public:
    static uint8_t calculate_profile_01(buffer_view _buffer_view,
            const uint8_t _start_value = 0x00U);
    static uint32_t calculate_profile_04(buffer_view _buffer_view,
            const uint32_t _start_value = 0x00000000U);
    static uint16_t calculate_profile_05(buffer_view _buffer_view,
            const uint16_t _start_value = 0xFFFFU);
    static uint64_t calculate_profile_07(buffer_view _buffer_view,
            const uint64_t _start_value = 0x0000000000000000U);

    static uint32_t calculate_profile_custom(buffer_view _buffer_view);

  private:
    static const uint8_t  lookup_table_profile_01_[256];
    static const uint32_t lookup_table_profile_04_[256];
    static const uint16_t lookup_table_profile_05_[256];
    static const uint64_t lookup_table_profile_07_[256];
    static const uint32_t lookup_table_profile_custom_[256];

};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_E2E_CRC_HPP
