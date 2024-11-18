// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SERIALIZABLE_HPP_
#define VSOMEIP_V3_SERIALIZABLE_HPP_

#include <vsomeip/export.hpp>

namespace vsomeip_v3 {

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

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SERIALIZABLE_HPP_
