// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <cstdint>

#ifndef VSOMEIP_V3_SD_ENUMERATION_TYPES_HPP
#define VSOMEIP_V3_SD_ENUMERATION_TYPES_HPP

namespace vsomeip_v3 {
namespace sd {

enum class option_type_e
    : uint8_t {
        CONFIGURATION = 0x1,
    LOAD_BALANCING = 0x2,
    PROTECTION = 0x3,
    IP4_ENDPOINT = 0x4,
    IP6_ENDPOINT = 0x6,
    IP4_MULTICAST = 0x14,
    IP6_MULTICAST = 0x16,
    SELECTIVE = 0x20,
    UNKNOWN = 0xFF
};

enum class entry_type_e
    : uint8_t {
        FIND_SERVICE = 0x00,
    OFFER_SERVICE = 0x01,
    STOP_OFFER_SERVICE = 0x01,
    REQUEST_SERVICE = 0x2,
    FIND_EVENT_GROUP = 0x4,
    PUBLISH_EVENTGROUP = 0x5,
    STOP_PUBLISH_EVENTGROUP = 0x5,
    SUBSCRIBE_EVENTGROUP = 0x06,
    STOP_SUBSCRIBE_EVENTGROUP = 0x06,
    SUBSCRIBE_EVENTGROUP_ACK = 0x07,
    STOP_SUBSCRIBE_EVENTGROUP_ACK = 0x07,
    UNKNOWN = 0xFF
};

enum class layer_four_protocol_e
    : uint8_t {
        TCP = 0x06,
        UDP = 0x11,
        UNKNOWN = 0xFF
};

} // namespace sd
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SD_ENUMERATION_TYPES_HPP
