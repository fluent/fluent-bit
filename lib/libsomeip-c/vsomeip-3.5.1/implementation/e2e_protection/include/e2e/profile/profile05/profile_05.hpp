// Copyright (C) 2020-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_E2E_PROFILE05_PROFILE05_HPP
#define VSOMEIP_V3_E2E_PROFILE05_PROFILE05_HPP

#include <cstdint>

#include <vsomeip/defines.hpp>

#include "../../../buffer/buffer.hpp"

// The MSB of the dataID is the instance identifier.
// Therefore, the instance identifier must fit into a single byte.
#define VSOMEIP_E2E_PROFILE05_MAX_INSTANCE 0x00ff

namespace vsomeip_v3 {
namespace e2e {
namespace profile05 {

struct profile_config;

class profile_05 {
public:
    static uint16_t compute_crc(const profile_config &_config, const e2e_buffer &_buffer);

    static bool is_buffer_length_valid(const profile_config &_config, const e2e_buffer &_buffer);
};

struct profile_config {
    profile_config() = delete;

    profile_config(uint32_t _data_id, uint16_t _data_length,
            size_t _offset, uint16_t _max_delta_counter)

        : data_id_(_data_id), data_length_(_data_length),
          offset_(_offset), max_delta_counter_(_max_delta_counter),
          base_(VSOMEIP_SOMEIP_HEADER_SIZE) {
    }
    profile_config(const profile_config &_config) = default;
    profile_config &operator=(const profile_config &_config) = default;

    uint32_t data_id_;
    uint16_t data_length_;
    size_t offset_; // This must be configured in bit but as a multiple of 8.
                    // As we must use it as an index, we do the math once at
                    // configuration time and use the correct data type here.
                    // Thus, this value is always the byte where the CRC starts.
    uint16_t max_delta_counter_;

    // SOME/IP base
    size_t base_;
};

} // namespace profile_05
} // namespace e2e
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_E2E_PROFILE05_PROFILE05_HPP
