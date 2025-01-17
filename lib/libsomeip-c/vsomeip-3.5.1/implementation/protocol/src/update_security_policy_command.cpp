// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include "../include/update_security_policy_command.hpp"
#include "../../security/include/policy.hpp"

namespace vsomeip_v3 {
namespace protocol {

update_security_policy_command::update_security_policy_command(
        bool _is_internal)
    : command(_is_internal ?
            id_e::UPDATE_SECURITY_POLICY_INT_ID :
            id_e::UPDATE_SECURITY_POLICY_ID) {
}

void
update_security_policy_command::serialize(std::vector<byte_t> &_buffer,
        error_e &_error) const {

    std::vector<byte_t> its_policy_data;
    if (policy_) {
         if (policy_->serialize(its_policy_data)) {
             _error = error_e::ERROR_UNKNOWN;
             return;
         }
    }

    size_t its_size(COMMAND_HEADER_SIZE + sizeof(update_id_)
            + its_policy_data.size());

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
    its_offset += sizeof(update_id_);
    std::memcpy(&_buffer[its_offset],
            &its_policy_data[0], its_policy_data.size());
}

void
update_security_policy_command::deserialize(const std::vector<byte_t> &_buffer,
        error_e &_error) {

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
    policy_ = std::make_shared<policy>();
    const byte_t *its_policy_data
        = &_buffer[COMMAND_HEADER_SIZE + sizeof(update_id_)];
    uint32_t its_policy_size
        = uint32_t(_buffer.size() - COMMAND_HEADER_SIZE - sizeof(update_id_));

    if (its_policy_size == 0
            || !policy_->deserialize(its_policy_data, its_policy_size)) {

        _error = error_e::ERROR_UNKNOWN;
        policy_.reset();
        return;
    }
}

uint32_t
update_security_policy_command::get_update_id() const {

    return update_id_;
}

void
update_security_policy_command::set_update_id(uint32_t _update_id) {

    update_id_ = _update_id;
}

std::shared_ptr<policy>
update_security_policy_command::get_policy() const {

    return policy_;
}

void
update_security_policy_command::set_policy(
        const std::shared_ptr<policy> &_policy) {

    policy_ = _policy;
}

} // namespace protocol
} // namespace vsomeip
