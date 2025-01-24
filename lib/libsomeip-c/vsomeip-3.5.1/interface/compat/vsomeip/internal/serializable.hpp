// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_SERIALIZABLE_HPP
#define VSOMEIP_SERIALIZABLE_HPP

#include "../../../compat/vsomeip/export.hpp"

namespace vsomeip {

class serializer;

/**
 * Abstract base class for element that can be serialized.
 */
class serializable {
public:
    VSOMEIP_EXPORT virtual ~serializable() {}

    /**
     * \brief serialize the content of the object
     */
    VSOMEIP_EXPORT virtual bool serialize(serializer *_to) const = 0;
};

} // namespace vsomeip

#endif // VSOMEIP_SERIALIZABLE_HPP
