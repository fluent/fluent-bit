// Copyright (C) 2019 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_COMPAT_PAYLOAD_IMPL_HPP_
#define VSOMEIP_COMPAT_PAYLOAD_IMPL_HPP_

#include <compat/vsomeip/payload.hpp>
#include <vsomeip/payload.hpp>

namespace vsomeip {

class payload_impl
        : public payload {

public:
    payload_impl(const std::shared_ptr<vsomeip_v3::payload> &_impl);
    ~payload_impl();

    bool operator ==(const payload &_other);

    byte_t * get_data();
    const byte_t * get_data() const;

    void set_data(const byte_t *_data, length_t _length);
    void set_data(const std::vector<byte_t> &_data);
    void set_data(std::vector<byte_t> &&_data);

    length_t get_length() const;
    void set_capacity(length_t _length);

    bool deserialize(deserializer *_from);
    bool serialize(serializer *_to) const;

    // Wraps
    inline std::shared_ptr<vsomeip_v3::payload> get_impl() const { return impl_; }

private:
    std::shared_ptr<vsomeip_v3::payload> impl_;
};

} // namespace vsomeip

#endif // VSOMEIP_COMPAT_PAYLOAD_IMPL_HPP_
