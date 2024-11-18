// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/internal/logger.hpp>

#include "../include/message_impl.hpp"
#include "../include/payload_impl.hpp"
#ifdef ANDROID
#    include "../../../configuration/include/internal_android.hpp"
#else
#    include "../../../configuration/include/internal.hpp"
#endif
#include "../../../message/include/message_impl.hpp"

namespace vsomeip {

message_impl::message_impl(const std::shared_ptr<vsomeip_v3::message> &_impl)
    : message_base_impl(_impl) {
}

message_impl::~message_impl() {
}

std::shared_ptr< payload >
message_impl::get_payload() const {

    return std::make_shared<payload_impl>(impl_->get_payload());
}

void
message_impl::set_payload(std::shared_ptr< payload > _payload) {

    if (_payload) {
        auto its_payload = std::dynamic_pointer_cast<payload_impl>(_payload);
        impl_->set_payload(its_payload->get_impl());
    } else {
        impl_->set_payload(nullptr);
    }
}

bool
message_impl::serialize(serializer *_to) const {

    (void)_to;
    VSOMEIP_ERROR << "message_impl::" << __func__
            << ": Must not be called from compatibility layer.";
    return false;
}

bool
message_impl::deserialize(deserializer *_from) {

    (void)_from;
    VSOMEIP_ERROR << "message_impl::" << __func__
            << ": Must not be called from compatibility layer.";
    return false;
}

} // namespace vsomeip
