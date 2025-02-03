// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_DEFINES_HPP_
#define VSOMEIP_V3_DEFINES_HPP_

#include <cstddef>
#include <cstdint>

constexpr std::uint8_t VSOMEIP_PROTOCOL_VERSION          = 0x1;

// 0 = unlimited, if not specified otherwise via configuration file
constexpr std::size_t VSOMEIP_MAX_LOCAL_MESSAGE_SIZE     = 0;
// 0 = unlimited, if not specified otherwise via configuration file
constexpr std::size_t VSOMEIP_MAX_TCP_MESSAGE_SIZE       = 0;
constexpr std::size_t VSOMEIP_MAX_UDP_MESSAGE_SIZE       = 1416;

constexpr std::size_t VSOMEIP_PACKET_SIZE                = VSOMEIP_MAX_UDP_MESSAGE_SIZE;

constexpr std::size_t VSOMEIP_SOMEIP_MAGIC_COOKIE_SIZE   = 8;
constexpr std::uint32_t VSOMEIP_SOMEIP_HEADER_SIZE       = 8;
constexpr std::uint32_t VSOMEIP_FULL_HEADER_SIZE         = 16;

constexpr std::size_t VSOMEIP_SERVICE_POS_MIN            = 0;
constexpr std::size_t VSOMEIP_SERVICE_POS_MAX            = 1;
constexpr std::size_t VSOMEIP_METHOD_POS_MIN             = 2;
constexpr std::size_t VSOMEIP_METHOD_POS_MAX             = 3;
constexpr std::size_t VSOMEIP_EVENT_POS_MIN              = 2;
constexpr std::size_t VSOMEIP_EVENT_POS_MAX              = 3;
constexpr std::size_t VSOMEIP_LENGTH_POS_MIN             = 4;
constexpr std::size_t VSOMEIP_LENGTH_POS_MAX             = 7;
constexpr std::size_t VSOMEIP_CLIENT_POS_MIN             = 8;
constexpr std::size_t VSOMEIP_CLIENT_POS_MAX             = 9;
constexpr std::size_t VSOMEIP_SESSION_POS_MIN            = 10;
constexpr std::size_t VSOMEIP_SESSION_POS_MAX            = 11;
constexpr std::size_t VSOMEIP_PROTOCOL_VERSION_POS       = 12;
constexpr std::size_t VSOMEIP_INTERFACE_VERSION_POS      = 13;
constexpr std::size_t VSOMEIP_MESSAGE_TYPE_POS           = 14;
constexpr std::size_t VSOMEIP_RETURN_CODE_POS            = 15;
constexpr std::size_t VSOMEIP_PAYLOAD_POS                = 16;

#endif // VSOMEIP_V3_DEFINES_HPP_
