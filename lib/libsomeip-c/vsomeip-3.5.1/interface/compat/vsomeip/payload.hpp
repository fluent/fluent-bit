// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_PAYLOAD_HPP
#define VSOMEIP_PAYLOAD_HPP

#include <vector>

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
 *
 * \brief This class implements an array of bytes to be used as
 * payload for SOME/IP messages.
 *
*/
class payload: public serializable, public deserializable {
public:
    VSOMEIP_EXPORT virtual ~payload() {}

    /**
     * \brief Returns true if the given payload is equal to this one.
     *
     * \param _other Payload that shall be compared to this payload.
     */
    VSOMEIP_EXPORT virtual bool operator ==(const payload &_other) = 0;

    /**
     * \brief Returns pointer to the payload content
     */
    VSOMEIP_EXPORT virtual byte_t * get_data() = 0;

    /**
     * \brief Returns constant pointer to the payload content
     */
    VSOMEIP_EXPORT virtual const byte_t * get_data() const = 0;

    /**
     * \brief Copies the given data array to the payload object.
     *
     * The current payload content is replaced by the data provided.
     * The given buffer remains untouched.
     *
     * \param _data Pointer to a data buffer.
     * \param _length Length of the data buffer.
     */
    VSOMEIP_EXPORT virtual void set_data(const byte_t *_data,
            length_t _length) = 0;

    /**
     * \brief Copies the given data array to the payload object.
     *
     * The current payload content is replaced by the data provided.
     * The given buffer remains untouched.
     *
     * \param _data Vector containing the data
     */
    VSOMEIP_EXPORT virtual void set_data(
            const std::vector<byte_t> &_data) = 0;

    /**
     * \brief Returns the length of the payload content.
     */
    VSOMEIP_EXPORT virtual length_t get_length() const = 0;

    /**
     * \brief Set the maximum length of the payload content.
     *
     * This function must be called before directly copying data using the
     * pointer to the internal buffer.
     */
    VSOMEIP_EXPORT virtual void set_capacity(length_t _length) = 0;

    /**
     * \brief Moves the given data array to the payload object.
     *
     * The current payload content is replaced by the data provided.
     * The given buffer is owned by the payload object afterwards.
     *
     * \param _data Vector containing the data
     */
    VSOMEIP_EXPORT virtual void set_data(
            std::vector<byte_t> &&_data) = 0;    
};

/** @} */

} // namespace vsomeip

#endif // VSOMEIP_PAYLOAD_HPP
