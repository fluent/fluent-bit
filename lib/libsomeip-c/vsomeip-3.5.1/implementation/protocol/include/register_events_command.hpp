// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PROTOCOL_REGISTER_EVENTS_COMMAND_HPP_
#define VSOMEIP_V3_PROTOCOL_REGISTER_EVENTS_COMMAND_HPP_

#include <set>

#include <vsomeip/enumeration_types.hpp>

#include "command.hpp"
#include "register_event.hpp"

namespace vsomeip_v3 {
namespace protocol {

class register_events_command
    : public command {
public:

    register_events_command();

    void serialize(std::vector<byte_t> &_buffer, error_e &_error) const;
    void deserialize(const std::vector<byte_t> &_buffer, error_e &_error);

    std::size_t get_num_registrations() const;

    bool add_registration(const register_event &_register_event);
    bool get_registration_at(std::size_t _position, register_event & _reg) const;

private:
    std::vector<register_event> registrations_;
};

} // namespace protocol
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PROTOCOL_REGISTER_EVENTS_COMMAND_HPP_
