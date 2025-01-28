// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_TRACE_ENUMERATION_TYPES_HPP_
#define VSOMEIP_V3_TRACE_ENUMERATION_TYPES_HPP_

namespace vsomeip_v3 {
namespace trace {

enum class filter_type_e : uint8_t {
    NEGATIVE = 0x00,
    POSITIVE = 0x01,
    HEADER_ONLY = 0x02
};

} // namespace trace
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_TRACE_ENUMERATION_TYPES_HPP_
