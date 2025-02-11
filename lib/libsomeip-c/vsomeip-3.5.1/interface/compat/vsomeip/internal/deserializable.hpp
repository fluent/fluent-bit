// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_DESERIALIZABLE_HPP
#define VSOMEIP_DESERIALIZABLE_HPP

#include "../../../compat/vsomeip/export.hpp"

namespace vsomeip {

class deserializer;

class deserializable {
public:
    VSOMEIP_EXPORT virtual ~deserializable() {
    }
    VSOMEIP_EXPORT virtual bool deserialize(deserializer *_from) = 0;
};

} // namespace vsomeip

#endif // VSOMEIP_SERIALIZABLE_HPP
