// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include "../include/security_policy_response_command_base.hpp"
#include "../../security/include/policy.hpp"

namespace vsomeip_v3 {
namespace protocol {

security_policy_response_command_base::security_policy_response_command_base(
        id_e _id)
    : command(_id) {
}

void
security_policy_response_command_base::serialize(std::vector<byte_t> &_buffer,
        error_e &_error) const {

    size_t its_size(COMMAND_HEADER_SIZE + sizeof(update_id_));

    if (its_size > std::numeric_limits<command_size_t>::max()) {

        _error = error_e::ERROR_MAX_COMMAND_SIZE_EXCEEDED;
        return;
    }

    // resize buffer
    _buffer.resize(its_size);

    // set size
    size_ = static_cast<command_size_t>(its_size - COMMAND_HEADER_SIZE);

    // serialize header
    command::serialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    // serialize payload
    size_t its_offset(COMMAND_HEADER_SIZE);
    std::memcpy(&_buffer[its_offset], &update_id_, sizeof(update_id_));
}

void
security_policy_response_command_base::deserialize(
        const std::vector<byte_t> &_buffer, error_e &_error) {

    if (COMMAND_HEADER_SIZE + sizeof(update_id_) > _buffer.size()) {

        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    // deserialize header
    command::deserialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    // deserialize payload
    std::memcpy(&update_id_, &_buffer[COMMAND_POSITION_PAYLOAD],
            sizeof(update_id_));
}

uint32_t
security_policy_response_command_base::get_update_id() const {

    return update_id_;
}

void
security_policy_response_command_base::set_update_id(uint32_t _update_id) {

    update_id_ = _update_id;
}

} // namespace protocol
} // namespace vsomeip
