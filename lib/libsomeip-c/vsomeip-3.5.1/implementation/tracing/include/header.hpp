// Copyright (C) 2016-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_TRACE_HEADER_HPP_
#define VSOMEIP_V3_TRACE_HEADER_HPP_

#include <memory>

#include <vsomeip/primitive_types.hpp>

#include <boost/asio/ip/address_v4.hpp>

#define VSOMEIP_TRACE_HEADER_SIZE 10

namespace vsomeip_v3 {

class endpoint;

namespace trace {

enum class protocol_e : uint8_t {
    local = 0x0,
    udp = 0x1,
    tcp = 0x2,
    unknown = 0xFF
};

struct header {
    bool prepare(const std::shared_ptr<endpoint> &_endpoint, bool _is_sending,
            instance_t _instance);
    bool prepare(const endpoint* _endpoint, bool _is_sending,
            instance_t _instance);
    void prepare(const boost::asio::ip::address_v4 &_address,
                 std::uint16_t _port, protocol_e _protocol, bool _is_sending,
                 instance_t _instance);

    byte_t data_[VSOMEIP_TRACE_HEADER_SIZE];
};

} // namespace trace
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_TRACE_HEADER_HPP_
