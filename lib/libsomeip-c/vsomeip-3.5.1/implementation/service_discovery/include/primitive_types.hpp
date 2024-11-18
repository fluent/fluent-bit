// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <cstdint>

#ifndef VSOMEIP_V3_SD_PRIMITIVE_TYPES_HPP_
#define VSOMEIP_V3_SD_PRIMITIVE_TYPES_HPP_

namespace vsomeip_v3 {
namespace sd {

// Load balancing
typedef uint16_t priority_t;
typedef uint16_t weight_t;

// Protection
typedef uint32_t alive_counter_t;
typedef uint32_t crc_t;

//
typedef uint8_t flags_t;

} // namespace sd
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SD_PRIMITIVE_TYPES_HPP_
