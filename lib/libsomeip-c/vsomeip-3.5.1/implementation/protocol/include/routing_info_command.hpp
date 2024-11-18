// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PROTOCOL_ROUTING_INFO_COMMAND_HPP_
#define VSOMEIP_V3_PROTOCOL_ROUTING_INFO_COMMAND_HPP_

#include "command.hpp"
#include "routing_info_entry.hpp"

namespace vsomeip_v3 {
namespace protocol {

class routing_info_command
    : public command {
public:
    routing_info_command();

    // command
    void serialize(std::vector<byte_t> &_buffer, error_e &_error) const;
    void deserialize(const std::vector<byte_t> &_buffer, error_e &_error);

    // specific
    const std::vector<routing_info_entry> &get_entries() const;
    void set_entries(std::vector<routing_info_entry> &&_entries);
    void add_entry(const routing_info_entry &_entry);

private:
    std::vector<routing_info_entry> entries_;
};

} // namespace protocol
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PROTOCOL_ROUTING_INFO_COMMAND_HPP_
