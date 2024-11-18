// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/constants.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../include/constants.hpp"
#include "../include/ip_option_impl.hpp"
#include "../../message/include/deserializer.hpp"
#include "../../message/include/serializer.hpp"


namespace vsomeip_v3 {
namespace sd {

ip_option_impl::ip_option_impl()
    : protocol_(layer_four_protocol_e::UNKNOWN), port_(0) {
}

ip_option_impl::ip_option_impl(const uint16_t _port, const bool _is_reliable)
    : protocol_(_is_reliable ?
          layer_four_protocol_e::TCP : layer_four_protocol_e::UDP),
      port_(_port) {
}

ip_option_impl::~ip_option_impl() {
}

bool
ip_option_impl::equals(const option_impl &_other) const {
    bool is_equal(option_impl::equals(_other));

    if (is_equal) {
        const ip_option_impl &its_other
            = dynamic_cast<const ip_option_impl &>(_other);
        is_equal = (protocol_ == its_other.protocol_
                && port_ == its_other.port_);
    }
    return is_equal;
}

unsigned short ip_option_impl::get_port() const {
    return port_;
}

void ip_option_impl::set_port(unsigned short _port) {
    port_ = _port;
}

layer_four_protocol_e ip_option_impl::get_layer_four_protocol() const {
    return protocol_;
}

void ip_option_impl::set_layer_four_protocol(
        layer_four_protocol_e _protocol) {
    protocol_ = _protocol;
}

} // namespace sd
} // namespace vsomeip_v3
