// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_DESERIALIZER_HPP
#define VSOMEIP_V3_DESERIALIZER_HPP

#include <vector>

#include <vsomeip/export.hpp>
#include <vsomeip/primitive_types.hpp>

#if defined(__QNX__)
#include "../../utility/include/qnx_helper.hpp"
#endif

namespace vsomeip_v3 {

class message_impl;

class deserializer {
public:
    VSOMEIP_EXPORT deserializer(std::uint32_t _buffer_shrink_threshold);
    VSOMEIP_EXPORT deserializer(byte_t *_data, std::size_t _length,
                                std::uint32_t _buffer_shrink_threshold);
    VSOMEIP_EXPORT deserializer(const deserializer& _other);
    VSOMEIP_EXPORT virtual ~deserializer();

    VSOMEIP_EXPORT void set_data(const byte_t *_data, std::size_t _length);
    VSOMEIP_EXPORT void set_data(const std::vector<byte_t> &_data);
    VSOMEIP_EXPORT void append_data(const byte_t *_data, std::size_t _length);
    VSOMEIP_EXPORT void drop_data(std::size_t _length);

    VSOMEIP_EXPORT std::size_t get_available() const;
    VSOMEIP_EXPORT std::size_t get_remaining() const;
    VSOMEIP_EXPORT void set_remaining(std::size_t _remaining);

    // to be used by applications to deserialize a message
    VSOMEIP_EXPORT message_impl *deserialize_message();

    // to be used (internally) by objects to deserialize their members
    // Note: this needs to be encapsulated!
    VSOMEIP_EXPORT bool deserialize(uint8_t& _value);
    VSOMEIP_EXPORT bool deserialize(uint16_t& _value);
    VSOMEIP_EXPORT bool deserialize(uint32_t& _value,
            bool _omit_last_byte = false);
    VSOMEIP_EXPORT bool deserialize(uint8_t *_data, std::size_t _length);
    VSOMEIP_EXPORT bool deserialize(std::string& _target, std::size_t _length);
    VSOMEIP_EXPORT bool deserialize(std::vector<uint8_t>& _value);

    VSOMEIP_EXPORT bool look_ahead(std::size_t _index, uint8_t &_value) const;
    VSOMEIP_EXPORT bool look_ahead(std::size_t _index, uint16_t &_value) const;
    VSOMEIP_EXPORT bool look_ahead(std::size_t _index, uint32_t &_value) const;

    VSOMEIP_EXPORT void reset();

#ifdef VSOMEIP_DEBUGGING
    VSOMEIP_EXPORT void show() const;
#endif
protected:
    std::vector<byte_t> data_;
    std::vector<byte_t>::iterator position_;
    std::size_t remaining_;
private:
    const std::uint32_t buffer_shrink_threshold_;
    std::uint32_t shrink_count_;

};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_DESERIALIZER_HPP
