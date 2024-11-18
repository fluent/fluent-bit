// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <cstring>

#include "../include/deserializer.hpp"
#include "../include/payload_impl.hpp"
#include "../include/serializer.hpp"

namespace vsomeip_v3 {

payload_impl::payload_impl()
    : data_() {
}

payload_impl::payload_impl(const byte_t* _data, uint32_t _size) {
    data_.assign(_data, _data + _size);
}

payload_impl::payload_impl(const std::vector<byte_t>& _data)
    : data_(_data) {
}

payload_impl::payload_impl(const payload_impl& _payload)
    : data_(_payload.data_) {
}

bool payload_impl::operator==(const payload& _other) {
    bool is_equal {get_length() == _other.get_length()};
    if (is_equal) {
        is_equal = (0 == std::memcmp(get_data(), _other.get_data(), get_length()));
    }
    return is_equal;
}

byte_t* payload_impl::get_data() {
    return data_.data();
}

const byte_t* payload_impl::get_data() const {
    return data_.data();
}

length_t payload_impl::get_length() const {
    return length_t(data_.size());
}

void payload_impl::set_capacity(length_t _capacity) {
    data_.reserve(_capacity);
}

void payload_impl::set_data(const byte_t* _data, const length_t _length) {
    data_.assign(_data, _data + _length);
}

void payload_impl::set_data(const std::vector<byte_t>& _data) {
    data_ = _data;
}

void payload_impl::set_data(std::vector<byte_t>&& _data) {
    data_ = std::move(_data);
}

bool payload_impl::serialize(serializer* _to) const {
    return (0 != _to && _to->serialize(data_));
}

bool payload_impl::deserialize(deserializer* _from) {
    return (0 != _from && _from->deserialize(data_));
}

} // namespace vsomeip_v3
