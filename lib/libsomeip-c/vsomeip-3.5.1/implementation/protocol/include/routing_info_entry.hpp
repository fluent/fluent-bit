// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PROTOCOL_ROUTING_INFO_ENTRY_HPP_
#define VSOMEIP_V3_PROTOCOL_ROUTING_INFO_ENTRY_HPP_

#include <vector>

#include <boost/asio/ip/address.hpp>

#include "protocol.hpp"

namespace vsomeip_v3 {
namespace protocol {

class routing_info_entry {
public:
    routing_info_entry();
    routing_info_entry(const routing_info_entry &_source);

    void serialize(std::vector<byte_t> &_buffer, size_t &_index,
            error_e &_error) const;
    void deserialize(const std::vector<byte_t> &_buffer, size_t &_index,
            error_e &_error);

    routing_info_entry_type_e get_type() const;
    void set_type(routing_info_entry_type_e _type);

    size_t get_size() const;

    client_t get_client() const;
    void set_client(client_t _client);

    boost::asio::ip::address get_address() const;
    void set_address(const boost::asio::ip::address &_address);

    port_t get_port() const;
    void set_port(port_t _port);

    const std::vector<service> &get_services() const;
    void add_service(const service &_service);

private:
    routing_info_entry_type_e type_;

    client_t client_;

    boost::asio::ip::address address_;
    port_t port_;

    std::vector<service> services_;
};

} // namespace protocol
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PROTOCOL_ROUTING_INFO_ENTRY_HPP_
