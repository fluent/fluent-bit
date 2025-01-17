// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_MESSAGE_HPP
#define VSOMEIP_MESSAGE_HPP

#include <memory>

#include "../../compat/vsomeip/message_base.hpp"

namespace vsomeip {

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
};

/** @} */

} // namespace vsomeip

#endif // VSOMEIP_MESSAGE_HPP
