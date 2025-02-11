// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/payload.hpp>
#include <vsomeip/runtime.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../include/payload_impl.hpp"
#ifdef ANDROID
#    include "../../../configuration/include/internal_android.hpp"
#else
#    include "../../../configuration/include/internal.hpp"
#endif

namespace vsomeip {

payload_impl::payload_impl(const std::shared_ptr<vsomeip_v3::payload> &_impl)
    : impl_(_impl) {
}

payload_impl::~payload_impl() {
}

bool
payload_impl::operator==(const payload &_other) {

    bool is_equal(true);
    try {
        const payload_impl &other = dynamic_cast< const payload_impl & >(_other);
        is_equal = (*(impl_.get()) == *(other.impl_.get()));
    }
    catch (...) {
        is_equal = false;
    }
    return is_equal;
}

byte_t *
payload_impl::get_data() {

    return impl_->get_data();
}

const byte_t *
payload_impl::get_data() const {

    return impl_->get_data();
}

length_t
payload_impl::get_length() const {

    return impl_->get_length();
}

void
payload_impl::set_capacity(length_t _capacity) {

    impl_->set_capacity(_capacity);
}

void
payload_impl::set_data(const byte_t *_data, const length_t _length) {

    impl_->set_data(_data, _length);
}

void
payload_impl::set_data(const std::vector< byte_t > &_data) {

    impl_->set_data(_data);
}

void
payload_impl::set_data(std::vector< byte_t > &&_data) {

    impl_->set_data(_data);
}

bool
payload_impl::serialize(serializer *_to) const {

    (void)_to;
    VSOMEIP_ERROR << "payload_impl::" << __func__
            << ": Must not be called from compatibility layer.";
    return false;
}

bool
payload_impl::deserialize(deserializer *_from) {

    (void)_from;
    VSOMEIP_ERROR << "payload_impl::" << __func__
            << ": Must not be called from compatibility layer.";
    return false;
}

} // namespace vsomeip
