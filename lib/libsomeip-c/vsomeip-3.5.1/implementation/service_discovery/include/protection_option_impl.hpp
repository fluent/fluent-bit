// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SD_PROTECTION_OPTION_IMPL_HPP_
#define VSOMEIP_V3_SD_PROTECTION_OPTION_IMPL_HPP_

#include "../include/primitive_types.hpp"
#include "../include/option_impl.hpp"

namespace vsomeip_v3 {
namespace sd {

class protection_option_impl: public option_impl {
public:
    protection_option_impl();
    virtual ~protection_option_impl();

    bool equals(const option_impl &_other) const;

    alive_counter_t get_alive_counter() const;
    void set_alive_counter(alive_counter_t _counter);

    crc_t get_crc() const;
    void set_crc(crc_t _crc);

    bool serialize(vsomeip_v3::serializer *_to) const;
    bool deserialize(vsomeip_v3::deserializer *_from);

private:
    alive_counter_t counter_;
    crc_t crc_;
};

} // namespace sd
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SD_PROTECTION_OPTION_IMPL_HPP_
