// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PROTOCOL_PROTOCOL_HPP_
#define VSOMEIP_V3_PROTOCOL_PROTOCOL_HPP_

#include <vsomeip/constants.hpp>
#include <vsomeip/primitive_types.hpp>

namespace vsomeip_v3 {
namespace protocol {

typedef uint16_t version_t;
typedef uint32_t command_size_t;

enum class id_e : uint8_t {
    ASSIGN_CLIENT_ID = 0x00,
    ASSIGN_CLIENT_ACK_ID = 0x01,
    REGISTER_APPLICATION_ID = 0x02,
    DEREGISTER_APPLICATION_ID = 0x03,
    // APPLICATION_LOST_ID = 0x04,
    ROUTING_INFO_ID = 0x05,
    REGISTERED_ACK_ID = 0x06,
    PING_ID = 0x07,
    PONG_ID = 0x08,
    OFFER_SERVICE_ID = 0x10,
    STOP_OFFER_SERVICE_ID = 0x11,
    SUBSCRIBE_ID = 0x12,
    UNSUBSCRIBE_ID = 0x13,
    REQUEST_SERVICE_ID = 0x14,
    RELEASE_SERVICE_ID = 0x15,
    SUBSCRIBE_NACK_ID = 0x16,
    SUBSCRIBE_ACK_ID = 0x17,
    SEND_ID = 0x18,
    NOTIFY_ID = 0x19,
    NOTIFY_ONE_ID = 0x1A,
    REGISTER_EVENT_ID = 0x1B,
    UNREGISTER_EVENT_ID = 0x1C,
    ID_RESPONSE_ID = 0x1D,
    ID_REQUEST_ID = 0x1E,
    OFFERED_SERVICES_REQUEST_ID = 0x1F,
    OFFERED_SERVICES_RESPONSE_ID = 0x20,
    UNSUBSCRIBE_ACK_ID = 0x21,
    RESEND_PROVIDED_EVENTS_ID = 0x22,
    UPDATE_SECURITY_POLICY_ID = 0x23,
    UPDATE_SECURITY_POLICY_RESPONSE_ID = 0x24,
    REMOVE_SECURITY_POLICY_ID = 0x25,
    REMOVE_SECURITY_POLICY_RESPONSE_ID = 0x26,
    UPDATE_SECURITY_CREDENTIALS_ID = 0x27,
    DISTRIBUTE_SECURITY_POLICIES_ID = 0x28,
    UPDATE_SECURITY_POLICY_INT_ID = 0x29,
    EXPIRE_ID = 0x2A,
    SUSPEND_ID = 0x30,
    CONFIG_ID = 0x31,
    UNKNOWN_ID = 0xFF
};

enum class error_e : uint8_t {
    ERROR_OK = 0x00,
    ERROR_NOT_ENOUGH_BYTES = 0x01,
    ERROR_MAX_COMMAND_SIZE_EXCEEDED = 0x02,
    ERROR_MISMATCH = 0x04,
    ERROR_MALFORMED = 0x08,
    ERROR_NOT_ALLOWED = 0x10,
    ERROR_UNKNOWN = 0xff
};

enum class routing_info_entry_type_e : std::uint8_t {
    RIE_ADD_CLIENT = 0x00,
    RIE_DELETE_CLIENT = 0x01,
    RIE_ADD_SERVICE_INSTANCE = 0x02,
    RIE_DELETE_SERVICE_INSTANCE = 0x04,
    RIE_UNKNOWN = 0xff
};

typedef uint16_t pending_id_t;

struct service {
    service_t service_;
    instance_t instance_;
    major_version_t major_;
    minor_version_t minor_;

    service()
        : service_(ANY_SERVICE),
          instance_(ANY_INSTANCE),
          major_(ANY_MAJOR),
          minor_(ANY_MINOR) {
    }

    service(service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor)
        : service_(_service),
          instance_(_instance),
          major_(_major),
          minor_(_minor) {
    }

    bool operator<(const service &_other) const {

        return (service_ < _other.service_
                || (service_ == _other.service_
                        && instance_ < _other.instance_));
    }
};

static const version_t MAX_SUPPORTED_VERSION = 0;

static const size_t TAG_SIZE = 4;
static const size_t COMMAND_HEADER_SIZE = 9;
static const size_t SEND_COMMAND_HEADER_SIZE = 15;
static const size_t ROUTING_INFO_ENTRY_HEADER_SIZE = 7;

static const size_t COMMAND_POSITION_ID = 0;
static const size_t COMMAND_POSITION_VERSION = 1;
static const size_t COMMAND_POSITION_CLIENT = 3;
static const size_t COMMAND_POSITION_SIZE = 5;
static const size_t COMMAND_POSITION_PAYLOAD = 9;

static inline id_e get_command(byte_t _byte) {

    id_e its_id(id_e::UNKNOWN_ID);
    if (_byte <= static_cast<byte_t>(id_e::SUSPEND_ID))
        its_id = static_cast<id_e>(_byte);
    return its_id;
}

static inline bool operator==(const byte_t &_lhs, const id_e &_rhs) {

    return (_lhs == static_cast<byte_t>(_rhs));
}

static inline bool operator==(const id_e &_lhs, const byte_t &_rhs) {

    return (_rhs == _lhs);
}

} // namespace protocol
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PROTOCOL_PROTOCOL_HPP_
