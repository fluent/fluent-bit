// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PAYLOAD_IMPL_HPP
#define VSOMEIP_V3_PAYLOAD_IMPL_HPP

#include <vsomeip/export.hpp>
#include <vsomeip/payload.hpp>

#if defined(__QNX__)
#include "../../utility/include/qnx_helper.hpp"
#endif

namespace vsomeip_v3 {

class serializer;
class deserializer;

class payload_impl: public payload {
public:
    VSOMEIP_EXPORT payload_impl();
    VSOMEIP_EXPORT payload_impl(const byte_t* _data, uint32_t _size);
    VSOMEIP_EXPORT payload_impl(const std::vector<byte_t>& _data);
    VSOMEIP_EXPORT payload_impl(const payload_impl& _payload);
    VSOMEIP_EXPORT virtual ~payload_impl() = default;

    VSOMEIP_EXPORT bool operator== (const payload& _other);

    VSOMEIP_EXPORT byte_t* get_data();
    VSOMEIP_EXPORT const byte_t* get_data() const;
    VSOMEIP_EXPORT length_t get_length() const;

    VSOMEIP_EXPORT void set_capacity(length_t _capacity);

    VSOMEIP_EXPORT void set_data(const byte_t* _data, length_t _length);
    VSOMEIP_EXPORT void set_data(const std::vector<byte_t>& _data);
    VSOMEIP_EXPORT void set_data(std::vector<byte_t>&& _data);

    VSOMEIP_EXPORT bool serialize(serializer* _to) const;
    VSOMEIP_EXPORT bool deserialize(deserializer* _from);

private:
    std::vector<byte_t> data_;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PAYLOAD_IMPL_HPP
