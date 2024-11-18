// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/serviceentry_impl.hpp"
#include "../../message/include/deserializer.hpp"
#include "../../message/include/serializer.hpp"

namespace vsomeip_v3 {
namespace sd {

serviceentry_impl::serviceentry_impl() {
    minor_version_ = 0;
}

serviceentry_impl::~serviceentry_impl() {
}

minor_version_t serviceentry_impl::get_minor_version() const {
    return minor_version_;
}

void serviceentry_impl::set_minor_version(minor_version_t _version) {
    minor_version_ = _version;
}

bool serviceentry_impl::serialize(vsomeip_v3::serializer *_to) const {
    bool is_successful = entry_impl::serialize(_to);

    is_successful = is_successful
            && _to->serialize(static_cast<uint8_t>(major_version_));
    is_successful = is_successful
            && _to->serialize(static_cast<uint32_t>(ttl_), true);
    is_successful = is_successful
            && _to->serialize(static_cast<uint32_t>(minor_version_));

    return is_successful;
}

bool serviceentry_impl::deserialize(vsomeip_v3::deserializer *_from) {
    bool is_successful = entry_impl::deserialize(_from);

    uint8_t tmp_major_version(0);
    is_successful = is_successful && _from->deserialize(tmp_major_version);
    major_version_ = static_cast<major_version_t>(tmp_major_version);

    uint32_t tmp_ttl(0);
    is_successful = is_successful && _from->deserialize(tmp_ttl, true);
    ttl_ = static_cast<ttl_t>(tmp_ttl);

    uint32_t tmp_minor_version(0);
    is_successful = is_successful && _from->deserialize(tmp_minor_version);
    minor_version_ = static_cast<minor_version_t>(tmp_minor_version);

    return is_successful;
}

} // namespace sd
} // namespace vsomeip_v3
