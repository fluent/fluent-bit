// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_MESSAGE_HPP_
#define VSOMEIP_V3_MESSAGE_HPP_

#include <memory>

#include <vsomeip/deprecated.hpp>
#include <vsomeip/message_base.hpp>
#include <vsomeip/vsomeip_sec.h>

namespace vsomeip_v3 {

class payload;

/**
 *
 * \defgroup vsomeip
 *
 * @{
 *
 */

/**
 * \brief Implements regular SOME/IP messages.
 *
 * This class extends @ref message_base by an unstructured payload. Except
 * SOME/IP Service Discovery messages, all SOME/IP messages within vsomeip
 * are represented by message objects.
 */

class message: virtual public message_base {
public:
    virtual ~message() {}

    /**
     * \brief Returns a pointer to the message payload.
     */
    virtual std::shared_ptr<payload> get_payload() const = 0;

    /**
     * \brief Set the message payload.
     */
    virtual void set_payload(std::shared_ptr<payload> _payload) = 0;

    /**
     * \brief Get e2e protection check result.
     */
    VSOMEIP_EXPORT virtual uint8_t get_check_result() const = 0;

    /**
     * \brief Set e2e protection check result.
     */
    VSOMEIP_EXPORT virtual void set_check_result(uint8_t _check_result) = 0;

    /**
     * \brief Return whether or not the CRC value received is valid.
     */
    VSOMEIP_EXPORT virtual bool is_valid_crc() const = 0;

    /**
     * \brief Return uid of the message sender.
     */
    VSOMEIP_DEPRECATED_UID_GID VSOMEIP_EXPORT virtual uid_t get_uid() const = 0;

    /**
     * \brief Return gid of the message sender.
     */
    VSOMEIP_DEPRECATED_UID_GID VSOMEIP_EXPORT virtual gid_t get_gid() const = 0;

    /**
     * \brief Return environment (hostname) of the message sender.
     */
    VSOMEIP_EXPORT virtual std::string get_env() const = 0;

    /**
     * \brief Return security client of the message sender.
     */
    VSOMEIP_EXPORT virtual vsomeip_sec_client_t get_sec_client() const = 0;
};

/** @} */

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_MESSAGE_HPP_
