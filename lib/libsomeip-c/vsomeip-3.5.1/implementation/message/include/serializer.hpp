// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SERIALIZER_HPP
#define VSOMEIP_V3_SERIALIZER_HPP

#include <vector>

#include <vsomeip/export.hpp>
#include <vsomeip/primitive_types.hpp>

namespace vsomeip_v3 {

class serializable;

class  VSOMEIP_IMPORT_EXPORT serializer {
public:
    serializer(std::uint32_t _buffer_shrink_threshold);
    virtual ~serializer();

    bool serialize(const serializable *_from);

    bool serialize(const uint8_t _value);
    bool serialize(const uint16_t _value);
    bool serialize(const uint32_t _value, bool _omit_last_byte = false);
    bool serialize(const uint8_t *_data, uint32_t _length);
    bool serialize(const std::vector<byte_t> &_data);

    virtual const uint8_t * get_data() const;
    virtual uint32_t get_capacity() const;
    virtual uint32_t get_size() const;

    virtual void set_data(uint8_t *_data, uint32_t _capacity);

    virtual void reset();

#ifdef VSOMEIP_DEBUGGING
    virtual void show();
#endif
private:
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable : 4251)
#endif
    std::vector<byte_t> data_;
    std::uint32_t shrink_count_;
    std::uint32_t buffer_shrink_threshold_;
#ifdef _WIN32
#pragma warning(pop)
#endif
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SERIALIZER_IMPL_HPP
