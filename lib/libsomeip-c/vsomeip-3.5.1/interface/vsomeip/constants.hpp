// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_CONSTANTS_HPP_
#define VSOMEIP_V3_CONSTANTS_HPP_

#include <string>

#include <vsomeip/primitive_types.hpp>
#include <vsomeip/enumeration_types.hpp>

namespace vsomeip_v3 {

inline constexpr major_version_t DEFAULT_MAJOR = 0x00;
inline constexpr minor_version_t DEFAULT_MINOR = 0x00000000;
inline constexpr ttl_t DEFAULT_TTL = 0xFFFFFF; // "until next reboot"

const std::string DEFAULT_MULTICAST = "224.0.0.0";
inline constexpr uint16_t DEFAULT_PORT = 30500;
inline constexpr uint16_t ILLEGAL_PORT = 0xFFFF;
inline constexpr uint16_t ANY_PORT = 0;

inline constexpr uint16_t NO_TRACE_FILTER_EXPRESSION = 0x0000;

inline constexpr service_t ANY_SERVICE = 0xFFFF;
inline constexpr instance_t ANY_INSTANCE = 0xFFFF;
inline constexpr eventgroup_t ANY_EVENTGROUP = 0xFFFF;
inline constexpr method_t ANY_METHOD = 0xFFFF;
inline constexpr major_version_t ANY_MAJOR = 0xFF;
inline constexpr minor_version_t ANY_MINOR = 0xFFFFFFFF;

inline constexpr eventgroup_t DEFAULT_EVENTGROUP = 0x0001;

inline constexpr client_t ILLEGAL_CLIENT = 0x0000;
inline constexpr method_t INVALID_METHOD = 0x0000;

inline constexpr byte_t MAGIC_COOKIE_CLIENT_MESSAGE = 0x00;
inline constexpr byte_t MAGIC_COOKIE_SERVICE_MESSAGE = 0x80;
inline constexpr length_t MAGIC_COOKIE_SIZE = 0x00000008;
inline constexpr request_t MAGIC_COOKIE_REQUEST = 0xDEADBEEF;
inline constexpr client_t MAGIC_COOKIE_CLIENT = 0xDEAD;
inline constexpr protocol_version_t MAGIC_COOKIE_PROTOCOL_VERSION = 0x01;
inline constexpr interface_version_t MAGIC_COOKIE_INTERFACE_VERSION = 0x01;
inline constexpr message_type_e MAGIC_COOKIE_CLIENT_MESSAGE_TYPE =
        message_type_e::MT_REQUEST_NO_RETURN;
inline constexpr message_type_e MAGIC_COOKIE_SERVICE_MESSAGE_TYPE =
        message_type_e::MT_NOTIFICATION;
inline constexpr return_code_e MAGIC_COOKIE_RETURN_CODE = return_code_e::E_OK;

inline constexpr byte_t CLIENT_COOKIE[] = { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
        0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x01, 0x01, 0x00 };

inline constexpr byte_t SERVICE_COOKIE[] = { 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x01, 0x02, 0x00 };

inline constexpr event_t ANY_EVENT = 0xFFFF;
inline constexpr client_t ANY_CLIENT = 0xFFFF;

inline constexpr int VSOMEIP_ALL = -1;

inline constexpr pending_security_update_id_t DEFAULT_SECURITY_UPDATE_ID = 0x0;

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_CONSTANTS_HPP_
