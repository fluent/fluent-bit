// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include <vsomeip/constants.hpp>

#include "../include/expire_command.hpp"

namespace vsomeip_v3 {
namespace protocol {

expire_command::expire_command()
    : subscribe_command_base(id_e::EXPIRE_ID) {
}

void
expire_command::serialize(std::vector<byte_t> &_buffer,
        error_e &_error) const {

    size_t its_size(COMMAND_HEADER_SIZE
            + sizeof(service_) + sizeof(instance_)
            + sizeof(eventgroup_) + sizeof(major_)
            + sizeof(event_) + sizeof(pending_id_));

    if (its_size > std::numeric_limits<command_size_t>::max()) {

        _error = error_e::ERROR_MAX_COMMAND_SIZE_EXCEEDED;
        return;
    }

    // resize buffer
    _buffer.resize(its_size);

    // set size
    size_ = static_cast<command_size_t>(its_size - COMMAND_HEADER_SIZE);

    // payload
    subscribe_command_base::serialize(_buffer, _error);
}

void
expire_command::deserialize(const std::vector<byte_t> &_buffer,
        error_e &_error) {

    size_t its_size(COMMAND_HEADER_SIZE
            + sizeof(service_) + sizeof(instance_)
            + sizeof(eventgroup_) + sizeof(major_)
            + sizeof(event_) + sizeof(pending_id_));

    if (its_size > _buffer.size()) {

        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    // deserialize header
    subscribe_command_base::deserialize(_buffer, _error);
}

} // namespace protocol
} // namespace vsomeip
