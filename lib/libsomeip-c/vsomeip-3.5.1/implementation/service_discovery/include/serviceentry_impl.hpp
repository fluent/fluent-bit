// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SD_SERVICEENTRY_IMPL_HPP
#define VSOMEIP_V3_SD_SERVICEENTRY_IMPL_HPP

#include "entry_impl.hpp"

namespace vsomeip_v3 {
namespace sd {

class serviceentry_impl: public entry_impl {
public:
    serviceentry_impl();
    virtual ~serviceentry_impl();

    minor_version_t get_minor_version() const;
    void set_minor_version(minor_version_t _version);

    bool serialize(vsomeip_v3::serializer *_to) const;
    bool deserialize(vsomeip_v3::deserializer *_from);

private:
    minor_version_t minor_version_;
};

} // namespace sd
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SD_SERVICEENTRY_IMPL_HPP
