// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SD_IPV3_OPTION_IMPL_HPP_
#define VSOMEIP_V3_SD_IPV3_OPTION_IMPL_HPP_

#include <boost/asio/ip/address.hpp>

#include <vsomeip/primitive_types.hpp>

#include "ip_option_impl.hpp"

namespace vsomeip_v3 {
namespace sd {

class ipv4_option_impl: public ip_option_impl {
public:
    ipv4_option_impl();
    ipv4_option_impl(const boost::asio::ip::address &_address,
            const uint16_t _port, const bool _is_reliable);
    virtual ~ipv4_option_impl();

    bool equals(const option_impl &_other) const;

    const ipv4_address_t & get_address() const;
    void set_address(const ipv4_address_t &_address);

    bool is_multicast() const;
    bool serialize(vsomeip_v3::serializer *_to) const;
    bool deserialize(vsomeip_v3::deserializer *_from);

private:
    ipv4_address_t address_;
};

} // namespace sd
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SD_IPV3_OPTION_IMPL_HPP_

