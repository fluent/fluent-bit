// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_CONSTANTS_HPP
#define VSOMEIP_CONSTANTS_HPP

#include <string>

#include "../../compat/vsomeip/enumeration_types.hpp"
#include "../../compat/vsomeip/primitive_types.hpp"

namespace vsomeip {

const major_version_t DEFAULT_MAJOR = 0x00;
const minor_version_t DEFAULT_MINOR = 0x00000000;
const ttl_t DEFAULT_TTL = 0xFFFFFF; // "until next reboot"

const std::string DEFAULT_MULTICAST = "224.0.0.0";
const uint16_t DEFAULT_PORT = 30500;
const uint16_t ILLEGAL_PORT = 0xFFFF;

const uint16_t NO_TRACE_FILTER_EXPRESSION = 0x0000;

const service_t ANY_SERVICE = 0xFFFF;
const instance_t ANY_INSTANCE = 0xFFFF;
const method_t ANY_METHOD = 0xFFFF;
const major_version_t ANY_MAJOR = 0xFF;
const minor_version_t ANY_MINOR = 0xFFFFFFFF;

const eventgroup_t DEFAULT_EVENTGROUP = 0x0001;

const client_t ILLEGAL_CLIENT = 0x0000;

const byte_t MAGIC_COOKIE_CLIENT_MESSAGE = 0x00;
const byte_t MAGIC_COOKIE_SERVICE_MESSAGE = 0x80;
const length_t MAGIC_COOKIE_SIZE = 0x00000008;
const request_t MAGIC_COOKIE_REQUEST = 0xDEADBEEF;
const client_t MAGIC_COOKIE_NETWORK_BYTE_ORDER = 0xADDE;
const protocol_version_t MAGIC_COOKIE_PROTOCOL_VERSION = 0x01;
const interface_version_t MAGIC_COOKIE_INTERFACE_VERSION = 0x01;
const message_type_e MAGIC_COOKIE_CLIENT_MESSAGE_TYPE =
        message_type_e::MT_REQUEST_NO_RETURN;
const message_type_e MAGIC_COOKIE_SERVICE_MESSAGE_TYPE =
        message_type_e::MT_NOTIFICATION;
const return_code_e MAGIC_COOKIE_RETURN_CODE = return_code_e::E_OK;

const byte_t CLIENT_COOKIE[] = { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
        0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x01, 0x01, 0x00 };

const byte_t SERVICE_COOKIE[] = { 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x01, 0x02, 0x00 };

const event_t ANY_EVENT = 0xFFFF;
const client_t ANY_CLIENT = 0xFFFF;

const pending_subscription_id_t DEFAULT_SUBSCRIPTION = 0x0;
const pending_security_update_id_t DEFAULT_SECURITY_UPDATE_ID = 0x0;

} // namespace vsomeip

#endif // VSOMEIP_CONSTANTS_HPP
