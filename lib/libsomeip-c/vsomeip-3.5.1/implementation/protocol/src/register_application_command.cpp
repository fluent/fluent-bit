// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include "../include/register_application_command.hpp"

namespace vsomeip_v3 {
namespace protocol {

register_application_command::register_application_command()
    : command(id_e::REGISTER_APPLICATION_ID),
      port_(ILLEGAL_PORT) {

}

void
register_application_command::serialize(std::vector<byte_t> &_buffer,
        error_e &_error) const {

    size_t its_size(COMMAND_HEADER_SIZE + sizeof(port_));

    if (its_size > std::numeric_limits<command_size_t>::max()) {

        _error = error_e::ERROR_MAX_COMMAND_SIZE_EXCEEDED;
        return;
    }

    // resize buffer
    _buffer.resize(its_size);

    // set size
    size_ = static_cast<command_size_t>(sizeof(port_));

    // serialize header
    command::serialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    // serialize payload
    std::memcpy(&_buffer[COMMAND_POSITION_PAYLOAD], &port_,
            sizeof(port_));

}

void
register_application_command::deserialize(const std::vector<byte_t> &_buffer,
        error_e &_error) {

    if (COMMAND_HEADER_SIZE + sizeof(port_) > _buffer.size()) {

        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    // deserialize header
    command::deserialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    // deserialize payload
    std::memcpy(&port_, &_buffer[COMMAND_POSITION_PAYLOAD],
            sizeof(port_));
}

port_t
register_application_command::get_port() const {

    return port_;
}

void
register_application_command::set_port(port_t _port) {

    port_ = _port;
}

} // namespace protocol
} // namespace vsomeip
