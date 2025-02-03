// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SD_CONSTANTS_HPP_
#define VSOMEIP_V3_SD_CONSTANTS_HPP_

#include <vsomeip/enumeration_types.hpp>
#include <vsomeip/primitive_types.hpp>

namespace vsomeip_v3 {
namespace sd {

const service_t service = 0xFFFF;
const instance_t instance = 0x0000;
const method_t method = 0x8100;
const client_t client = 0x0000;
const protocol_version_t protocol_version = 0x01;
const interface_version_t interface_version = 0x01;
const message_type_e message_type = message_type_e::MT_NOTIFICATION;
const return_code_e return_code = return_code_e::E_OK;

namespace protocol {

const uint8_t reserved_byte = 0x0;
const uint16_t reserved_word = 0x0;
const uint32_t reserved_long = 0x0;

const uint8_t tcp = 0x06;
const uint8_t udp = 0x11;

} // namespace protocol
} // namespace sd
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SD_CONSTANTS_HPP_
