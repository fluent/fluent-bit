// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_RUNTIME_HPP
#define VSOMEIP_V3_RUNTIME_HPP

#include <memory>
#include <string>
#include <vector>

#include <vsomeip/export.hpp>
#include <vsomeip/primitive_types.hpp>

namespace vsomeip_v3 {

class application;
class message;
class payload;

/**
 *
 * \defgroup vsomeip
 *
 * The vsomeip module contains all elements a user applications needs to:
 *
 * - offer SOME/IP service instances
 * - request SOME/IP service instances
 * - offer SOME/IP eventgroups
 * - subscribe to SOME/IP eventgroups
 * - send and receive SOME/IP messages (request/response)
 * - implement SOME/IP events and fields
 *
 * @{
 *
 */

/**
 *
 * \brief Singleton class containing all public resource management
 * facilities of vsomeip.
 *
 * The methods of this class shall be used to create instances of all the
 * classes needed to facilitate SOME/IP communication. In particular, it is
 * the entry point to create instances of the @ref application class that
 * contains the main public API of vsomeip.
 *
 */
class VSOMEIP_IMPORT_EXPORT runtime {
public:

    static std::string get_property(const std::string &_name);
    static void set_property(const std::string &_name, const std::string &_value);

    static std::shared_ptr<runtime> get();

    virtual ~runtime() {
    }

    /**
     *
     * \brief Creates a vsomeip application object.
     *
     * An application object manages service offers and requests as well as
     * event subscriptions. It allows to register user application functions
     * as callbacks that are called on specific events during runtime, e.g
     * to react on incoming SOME/IP messages.
     * An application object is identified by a unique name that is also used
     * in (and therefore has to match) the configuration files of vsomeip. If
     * the name is left empty, the application name is taken from the
     * environment variable "VSOMEIP_APPLICATION_NAME"
     *
     * \param _name Name of the application on the system.
     *
     */
    virtual std::shared_ptr<application> create_application(
            const std::string &_name = "") = 0;

    /**
     *
     * \brief Constructs an empty message object.
     *
     * The message can then be used to call @application::send to send a
     * SOME/IP message. The user application is responsible for setting
     * the message type, the service instance and the message payload
     * after this call and before calling @application::send.
     *
     * \param _reliable Determines whether this message shall be sent
     * over a reliable connection (TCP) or not (UDP).
     *
     */
    virtual std::shared_ptr<message> create_message(
            bool _reliable = false) const = 0;
    /**
     *
     * \brief Constructs an empty request message.
     *
     * The message can then be used to call @ref application::send to send a
     * SOME/IP message. The message type is set to REQUEST after the
     * call and the request identifier is automatically set during the
     * @ref application::send call.
     *
     * The user application is responsible for setting the service instance
     * and the payload.
     *
     * \param _reliable Determines whether this message shall be sent
     * over a reliable connection (TCP) or not (UDP).
     *
     */
    virtual std::shared_ptr<message> create_request(
            bool _reliable = false) const = 0;

    /*
     * \brief Constructs an empty response message from a given request
     * message.
     *
     * The message can then be used to call @ref application::send to send a
     * SOME/IP message. The message type is set to RESPONSE after the
     * call and the request identifier is automatically set from the
     * request message.
     *
     * The user application is responsible for setting the service instance
     * and the payload.
     *
     * \param _request The request message that shall be answered by
     * the response message.
     *
     */
    virtual std::shared_ptr<message> create_response(
            const std::shared_ptr<message> &_request) const = 0;

    /**
     *
     * \brief Creates an empty notification message.
     *
     * The message can then be used to call @ref application::send to send a
     * SOME/IP message. The message type is set to NOTIFICATION after the
     * call.
     *
     * The user application is responsible for setting the service instance
     * and the payload.
     *
     * \param _reliable Determines whether this message shall be sent
     * over a reliable connection (TCP) or not (UDP).
     *
     * Note: Creating notification messages and sending them using
     * @ref application::send is possible but not the standard way of sending
     * notification with vsomeip. The standard way is calling
     * @ref application::offer_event and setting the value using the
     * @ref application::notify / @ref application::notify_one methods.
     *
     */
    virtual std::shared_ptr<message> create_notification(
            bool _reliable = false) const = 0;

    /**
     *
     * \brief Creates an empty payload object.
     *
     */
    virtual std::shared_ptr<payload> create_payload() const = 0;

    /**
     *
     * \brief Creates a payload object filled with the given data.
     *
     * \param _data Bytes to be copied into the payload object.
     * \param _size Number of bytes to be copied into the payload object.
     *
     */
    virtual std::shared_ptr<payload> create_payload(
            const byte_t *_data, uint32_t _size) const = 0;

    /**
     *
     * \brief Creates a payload object filled with the given data.
     *
     * \param _data Bytes to be copied into the payload object.
     *
     */
    virtual std::shared_ptr<payload> create_payload(
            const std::vector<byte_t> &_data) const = 0;

    /**
     *
     * \brief Retrieves the application object for the application with the
     * given name.
     *
     * If no such application is found, an empty shared_ptr is returned
     * (nullptr).
     *
     * \param _name Name of the application to be found.
     *
     */
    virtual std::shared_ptr<application> get_application(
            const std::string &_name) const = 0;

    /**
     *
     * \brief Removes the application object for the application with the
     * given name.
     *
     * If no such application is found, this is a null operation.
     *
     * \param _name Name of the application to be removed.
     *
     */
    virtual void remove_application( const std::string &_name) = 0;

    /**
     *
     * \brief Creates a vsomeip application object.
     *
     * An application object manages service offers and requests as well as
     * event subscriptions. It allows to register user application functions
     * as callbacks that are called on specific events during runtime, e.g
     * to react on incoming SOME/IP messages.
     * An application object is identified by a unique name that is also used
     * in (and therefore has to match) the configuration files of vsomeip. If
     * the name is left empty, the application name is taken from the
     * environment variable "VSOMEIP_APPLICATION_NAME"
     *
     * \param _name Name of the application on the system.
     * \param _path Path to the configuration file or folder.
     *
     */
    virtual std::shared_ptr<application> create_application(
            const std::string &_name, const std::string &_path) = 0;
};

/** @} */

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_RUNTIME_HPP_
