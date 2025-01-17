// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_E2E_PROFILE07_PROFILE07_HPP
#define VSOMEIP_V3_E2E_PROFILE07_PROFILE07_HPP

#include <cstdint>

#include <vsomeip/defines.hpp>

#include "../../../buffer/buffer.hpp"

namespace vsomeip_v3 {
namespace e2e {
namespace profile07 {

const uint8_t PROFILE_07_SIZE_OFFSET = 8;
const uint8_t PROFILE_07_COUNTER_OFFSET = 12;
const uint8_t PROFILE_07_DATAID_OFFSET = 16;
const uint8_t PROFILE_07_CRC_OFFSET = 0;

struct profile_config;

class profile_07 {
public:
    static uint64_t compute_crc(const profile_config &_config, const e2e_buffer &_buffer);
};

// [SWS_E2E_00200]
struct profile_config {
    profile_config() = delete;

    profile_config(uint32_t _data_id, size_t _offset,
            size_t _min_data_length, size_t _max_data_length,
            uint32_t _max_delta_counter)
        : data_id_(_data_id), offset_(_offset),
          min_data_length_(_min_data_length), max_data_length_(_max_data_length),
          max_delta_counter_(_max_delta_counter),
          base_(VSOMEIP_SOMEIP_HEADER_SIZE) {
    }
    profile_config(const profile_config &_config) = default;
    profile_config &operator=(const profile_config &_config) = default;

    uint32_t data_id_;
    size_t offset_; // This must be configured in bit but as a multiple of 8.
                    // As we must use it as an index, we do the math once at
                    // configuration time and use the correct data type here.
                    // Thus, this value is always the byte where the CRC starts.
    size_t min_data_length_;
    size_t max_data_length_;
    uint32_t max_delta_counter_;

    // SOME/IP base
    size_t base_;
};

} // namespace profile_07
} // namespace e2e
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_E2E_PROFILE07_PROFILE07_HPP
