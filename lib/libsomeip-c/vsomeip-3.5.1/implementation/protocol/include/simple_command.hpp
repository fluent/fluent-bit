// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PROTOCOL_SIMPLE_COMMAND_HPP_
#define VSOMEIP_V3_PROTOCOL_SIMPLE_COMMAND_HPP_

#include "command.hpp"

namespace vsomeip_v3 {
namespace protocol {

class simple_command
    : public command {
public:

    void serialize(std::vector<byte_t> &_buffer,
            error_e &_error) const;
    void deserialize(const std::vector<byte_t> &_buffer,
            error_e &_error);

protected:
    simple_command(id_e _id);
};

} // namespace protocol
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PROTOCOL_SIMPLE_COMMAND_HPP_
