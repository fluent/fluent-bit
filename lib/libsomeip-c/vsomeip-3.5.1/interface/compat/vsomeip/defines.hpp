// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_DEFINES_HPP
#define VSOMEIP_DEFINES_HPP

#define VSOMEIP_PROTOCOL_VERSION                0x1

// 0 = unlimited, if not specified otherwise via configuration file
#define VSOMEIP_MAX_LOCAL_MESSAGE_SIZE          0
// 0 = unlimited, if not specified otherwise via configuration file
#define VSOMEIP_MAX_TCP_MESSAGE_SIZE            0
#define VSOMEIP_MAX_UDP_MESSAGE_SIZE            1416

#define VSOMEIP_PACKET_SIZE                     VSOMEIP_MAX_UDP_MESSAGE_SIZE

#define VSOMEIP_SOMEIP_HEADER_SIZE              8
#define VSOMEIP_SOMEIP_MAGIC_COOKIE_SIZE        8
#define VSOMEIP_FULL_HEADER_SIZE                16

#define VSOMEIP_SERVICE_POS_MIN                 0
#define VSOMEIP_SERVICE_POS_MAX                 1
#define VSOMEIP_METHOD_POS_MIN                  2
#define VSOMEIP_METHOD_POS_MAX                  3
#define VSOMEIP_EVENT_POS_MIN                   2
#define VSOMEIP_EVENT_POS_MAX                   3
#define VSOMEIP_LENGTH_POS_MIN                  4
#define VSOMEIP_LENGTH_POS_MAX                  7
#define VSOMEIP_CLIENT_POS_MIN                  8
#define VSOMEIP_CLIENT_POS_MAX                  9
#define VSOMEIP_SESSION_POS_MIN                 10
#define VSOMEIP_SESSION_POS_MAX                 11
#define VSOMEIP_PROTOCOL_VERSION_POS            12
#define VSOMEIP_INTERFACE_VERSION_POS           13
#define VSOMEIP_MESSAGE_TYPE_POS                14
#define VSOMEIP_RETURN_CODE_POS                 15
#define VSOMEIP_PAYLOAD_POS                     16

#endif // VSOMEIP_DEFINES_HPP
