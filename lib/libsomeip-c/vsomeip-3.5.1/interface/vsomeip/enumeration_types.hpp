// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_ENUMERATION_TYPES_HPP_
#define VSOMEIP_V3_ENUMERATION_TYPES_HPP_

#include <cstdint>

namespace vsomeip_v3 {

enum class state_type_e : uint8_t {
    ST_REGISTERED = 0x0,
    ST_DEREGISTERED = 0x1
};

// SIP_RPC_684
enum class message_type_e : uint8_t {
    MT_REQUEST = 0x00,
    MT_REQUEST_NO_RETURN = 0x01,
    MT_NOTIFICATION = 0x02,
    MT_REQUEST_ACK = 0x40,
    MT_REQUEST_NO_RETURN_ACK = 0x41,
    MT_NOTIFICATION_ACK = 0x42,
    MT_RESPONSE = 0x80,
    MT_ERROR = 0x81,
    MT_RESPONSE_ACK = 0xC0,
    MT_ERROR_ACK = 0xC1,
    MT_UNKNOWN = 0xFF
};

// SIP_RPC_371
enum class return_code_e : uint8_t {
    E_OK = 0x00,
    E_NOT_OK = 0x01,
    E_UNKNOWN_SERVICE = 0x02,
    E_UNKNOWN_METHOD = 0x03,
    E_NOT_READY = 0x04,
    E_NOT_REACHABLE = 0x05,
    E_TIMEOUT = 0x06,
    E_WRONG_PROTOCOL_VERSION = 0x07,
    E_WRONG_INTERFACE_VERSION = 0x08,
    E_MALFORMED_MESSAGE = 0x09,
    E_WRONG_MESSAGE_TYPE = 0x0A,
    E_UNKNOWN = 0xFF
};

enum class routing_state_e : uint8_t {
    RS_RUNNING = 0x00,
    RS_SUSPENDED = 0x01,
    RS_RESUMED = 0x02,
    RS_SHUTDOWN = 0x03,
    RS_DIAGNOSIS = 0x04,
    RS_UNKNOWN = 0xFF
};

enum class offer_type_e : uint8_t {
    OT_LOCAL = 0x00,
    OT_REMOTE = 0x01,
    OT_ALL = 0x02,
};

enum class event_type_e : uint8_t {
    ET_EVENT = 0x00,
    ET_SELECTIVE_EVENT = 0x01,
    ET_FIELD = 0x02,
    ET_UNKNOWN = 0xFF
};

enum class security_mode_e : uint8_t {
    SM_OFF = 0x00,
    SM_ON = 0x01,
    SM_AUDIT = 0x02
};

enum class security_update_state_e : uint8_t {
    SU_SUCCESS = 0x00,
    SU_NOT_ALLOWED = 0x01,
    SU_UNKNOWN_USER_ID = 0x02,
    SU_INVALID_FORMAT = 0x03
};

enum class reliability_type_e : uint8_t {
    RT_RELIABLE = 0x01,
    RT_UNRELIABLE = 0x02,
    RT_BOTH = 0x3, // RT_RELIABLE | RT_UNRELIABLE
    RT_UNKNOWN = 0xFF
};

enum class availability_state_e : uint8_t {
    AS_UNAVAILABLE = 0x00, // unseen
    AS_OFFERED = 0x01,     // seen, but not requested/not yet usable
    AS_AVAILABLE = 0x02,   // seen and usable
    AS_UNKNOWN = 0xFF
};

enum class handler_registration_type_e : uint8_t {
    HRT_REPLACE = 0x00,
    HRT_PREPEND = 0x01,
    HRT_APPEND = 0x02,
    HRT_UNKNOWN = 0xFF
};

enum class endianess_e {
    be,     // big-endian
    le      // little-endian
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_ENUMERATION_TYPES_HPP_
