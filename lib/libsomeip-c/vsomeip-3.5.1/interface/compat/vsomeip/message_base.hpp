// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_MESSAGE_BASE_HPP
#define VSOMEIP_MESSAGE_BASE_HPP

#include "../../compat/vsomeip/enumeration_types.hpp"
#include "../../compat/vsomeip/export.hpp"
#include "../../compat/vsomeip/internal/deserializable.hpp"
#include "../../compat/vsomeip/internal/serializable.hpp"
#include "../../compat/vsomeip/primitive_types.hpp"

namespace vsomeip {

/**
 *
 * \defgroup vsomeip
 *
 * @{
 *
 */

/**
 * \brief Base class to implement SOME/IP messages.
 *
 * This class implements the SOME/IP message header and connects to the
 * serialzing/deserializing functionalities. The class is inherited by
 * the message classes within ::vsomeip and vsomeip::sd that add the
 * payload representations for regular and Service Discovery messages.
 */
class message_base
        : public serializable,
          public deserializable {
public:
    VSOMEIP_EXPORT virtual ~message_base() {};

    /**
     * \brief Returns the message identifier.
     *
     * The method returns the message identifier that consists of
     * service identifier and method identifier.
     */
    VSOMEIP_EXPORT virtual message_t get_message() const = 0;
    /**
     * \brief Set the message identifier.
     *
     * The methods sets service identifier and method identifier in
     * a single call.
     *
     * \param _message The new message identifier.
     */
    VSOMEIP_EXPORT virtual void set_message(message_t _message) = 0;

    /**
     * \brief Returns the service identifier from the message header.
     */
    VSOMEIP_EXPORT virtual service_t get_service() const = 0;

    /**
     * \brief Set the service identifier in the message header.
     */
    VSOMEIP_EXPORT virtual void set_service(service_t _service) = 0;

    /**
     * \brief Returns the instance identifier.
     *
     * The instance identifier is _not_ part of the SOME/IP header. It is
     * either derived from the incoming message (local) or from the port
     * that was used to send a message (external).
     */
    VSOMEIP_EXPORT virtual instance_t get_instance() const = 0;

    /**
     * \brief Set the instance identifier in the message header.
     *
     * To address the correct service instance, vsomeip uses the instance
     * identifier. For external services it is mapped to a IP address and port
     * combination before the message is sent. For internal messages is
     * transferred as additional data appended to the SOME/IP messages.
     * Therefore, before sending a message, a user application must set the
     * instance identifier.
     */
    VSOMEIP_EXPORT virtual void set_instance(instance_t _instance) = 0;

    /**
     * \brief Get the method/event identifier from the message header.
     */
    VSOMEIP_EXPORT virtual method_t get_method() const = 0;

    /**
     * \brief Set the method/event identifier in the message header.
     */
    VSOMEIP_EXPORT virtual void set_method(method_t _method) = 0;

    /**
     * \brief Get the payload length from the message header.
     */
    VSOMEIP_EXPORT virtual length_t get_length() const = 0;

    /**
     * \brief Get the request identifier from the message header.
     *
     * The request identifier consists of the client identifier and the
     * session identifier. As it does really make sense to set it as
     * a whole, setting is not supported.
     */
    VSOMEIP_EXPORT virtual request_t get_request() const = 0;

    /**
     * \brief Set the client identifier in the message header.
     */
    VSOMEIP_EXPORT virtual client_t get_client() const = 0;

    /**
     * \brief Set the client identifier in the message header.
     *
     * For requests this is automatically done by @ref application::send.
     * For notications this is not needed.
     */
    VSOMEIP_EXPORT virtual void set_client(client_t _client) = 0;

    /**
     * \brief Get the session identifier from the message header.
     */
    VSOMEIP_EXPORT virtual session_t get_session() const = 0;

    /**
     * \brief Set the session identifier in the message header.
     *
     * For requests this is automatically done by @ref application::send
     * For notifications it is not needed to set the session identifier.
     */
    VSOMEIP_EXPORT virtual void set_session(session_t _session) = 0;

    /**
     * \brief Get the protocol version from the message header.
     *
     * As the protocol version is a fixed value for a vsomeip implementation,
     * it cannot be set.
     */
    VSOMEIP_EXPORT virtual protocol_version_t get_protocol_version() const = 0;

    /**
     * \brief Get the interface version from the message header.
     */
    VSOMEIP_EXPORT virtual interface_version_t get_interface_version() const = 0;

    /**
     * \brief Set the interface version in the message header.
     */
    VSOMEIP_EXPORT virtual void set_interface_version(interface_version_t _version) = 0;

    /**
     * \brief Get the message type from the message header.
     */
    VSOMEIP_EXPORT virtual message_type_e get_message_type() const = 0;

    /**
     * \brief Set the message type in the message header.
     */
    VSOMEIP_EXPORT virtual void set_message_type(message_type_e _type) = 0;

    /**
     * \brief Get the return code from the message header.
     */
    VSOMEIP_EXPORT virtual return_code_e get_return_code() const = 0;

    /**
     * \brief Set the return code in the message header.
     */
    VSOMEIP_EXPORT virtual void set_return_code(return_code_e _code) = 0;

    /**
     * \brief Return the transport mode that was/will be used to send the message.
     */
    VSOMEIP_EXPORT virtual bool is_reliable() const = 0;

    /**
     * \brief Set the transport mode that will be used to send the message.
     */
    VSOMEIP_EXPORT virtual void set_reliable(bool _is_reliable) = 0;

    /**
     * \brief Return whether or not the message is an initial event.
     */
    VSOMEIP_EXPORT virtual bool is_initial() const = 0;

    /**
     * \brief Set whether or not the message is an initial event.
     */
    VSOMEIP_EXPORT virtual void set_initial(bool _is_initial) = 0;

    /**
     * \brief Return whether or not the CRC value received is valid.
     */
    VSOMEIP_EXPORT virtual bool is_valid_crc() const = 0;

    /**
     * \brief Set whether or not the CRC value received is valid.
     */
    VSOMEIP_EXPORT virtual void set_is_valid_crc(bool _is_valid_crc) = 0;

};

/** @} */

} // namespace vsomeip

#endif // VSOMEIP_MESSAGE_BASE_HPP
