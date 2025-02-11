// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PROTOCOL_REGISTER_APPLICATION_COMMAND_HPP_
#define VSOMEIP_V3_PROTOCOL_REGISTER_APPLICATION_COMMAND_HPP_

#include "command.hpp"

namespace vsomeip_v3 {
namespace protocol {

class register_application_command
    : public command {

public:
    register_application_command();

    void serialize(std::vector<byte_t> &_buffer, error_e &_error) const;
    void deserialize(const std::vector<byte_t> &_buffer, error_e &_error);

    port_t get_port() const;
    void set_port(port_t _port);

private:
    port_t port_;
};

} // namespace protocol
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PROTOCOL_REGISTER_APPLICATION_COMMAND_HPP_
