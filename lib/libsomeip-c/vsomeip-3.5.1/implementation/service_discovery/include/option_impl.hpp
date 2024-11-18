// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SD_OPTION_IMPL_HPP_
#define VSOMEIP_V3_SD_OPTION_IMPL_HPP_

#include <cstdint>
#include <memory>

#include "enumeration_types.hpp"
#include "message_element_impl.hpp"

namespace vsomeip_v3 {

class serializer;
class deserializer;

namespace sd {

class message_impl;

class option_impl: public message_element_impl {
public:
    option_impl();
    virtual ~option_impl();

    virtual bool equals(const option_impl &_other) const;

    uint16_t get_length() const;
    option_type_e get_type() const;

    inline uint32_t get_size() const {
        return static_cast<uint32_t>(length_) + 3;
    }

    virtual bool serialize(vsomeip_v3::serializer *_to) const;
    virtual bool deserialize(vsomeip_v3::deserializer *_from);

protected:
    uint16_t length_;
    option_type_e type_;
};

} // namespace sd
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SD_OPTION_IMPL_HPP_
