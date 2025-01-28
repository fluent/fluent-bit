// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/command.hpp"

namespace vsomeip_v3 {
namespace protocol {

command::command(id_e _id)
        : id_(_id),
          version_(MAX_SUPPORTED_VERSION),
          client_(0),
          size_(0) {
}

void
command::serialize(std::vector<byte_t> &_buffer,
        error_e &_error) const {

    // buffer space reservation is done within the code of
    // the derived classes that call this method

    _buffer[0] = static_cast<byte_t>(id_);
    std::memcpy(&_buffer[COMMAND_POSITION_VERSION], &version_,
            sizeof(version_));
    std::memcpy(&_buffer[COMMAND_POSITION_CLIENT], &client_,
            sizeof(client_));
    std::memcpy(&_buffer[COMMAND_POSITION_SIZE], &size_,
            sizeof(size_));

    _error = error_e::ERROR_OK;
}

void
command::deserialize(const std::vector<byte_t> &_buffer,
        error_e &_error) {

    // buffer size check (size >= header size) is
    // done within the code of the derived classes
    // that call this method

    // If the id_ is set to "UNKNOWN", read it.
    // Otherwise check it.
    if (id_ == id_e::UNKNOWN_ID) {

        id_ = static_cast<id_e>(_buffer[0]);
    } else if (_buffer[0] != static_cast<byte_t>(id_)) {

        _error = error_e::ERROR_MISMATCH;
        return;
    }

    std::memcpy(&version_, &_buffer[COMMAND_POSITION_VERSION],
            sizeof(version_));
    std::memcpy(&client_, &_buffer[COMMAND_POSITION_CLIENT],
            sizeof(client_));
    std::memcpy(&size_, &_buffer[COMMAND_POSITION_SIZE],
            sizeof(size_));

    _error = error_e::ERROR_OK;
}

} // namespace protocol
} // namespace vsomeip
