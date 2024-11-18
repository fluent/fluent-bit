// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include "../include/remove_security_policy_command.hpp"
#include "../../security/include/policy.hpp"

namespace vsomeip_v3 {
namespace protocol {

remove_security_policy_command::remove_security_policy_command()
    : command(id_e::REMOVE_SECURITY_POLICY_ID) {
}

void
remove_security_policy_command::serialize(std::vector<byte_t> &_buffer,
        error_e &_error) const {

    size_t its_size(COMMAND_HEADER_SIZE + sizeof(update_id_)
            + sizeof(uid_) + sizeof(gid_));

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
    std::memcpy(&_buffer[its_offset], &uid_, sizeof(uid_));
    its_offset += sizeof(uid_);
    std::memcpy(&_buffer[its_offset], &gid_, sizeof(gid_));
}

void
remove_security_policy_command::deserialize(const std::vector<byte_t> &_buffer,
        error_e &_error) {

    if (COMMAND_HEADER_SIZE + sizeof(update_id_)
            + sizeof(uid_) + sizeof(gid_t) > _buffer.size()) {

        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    // deserialize header
    command::deserialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    // deserialize payload
    size_t its_offset(COMMAND_HEADER_SIZE);
    std::memcpy(&update_id_, &_buffer[its_offset], sizeof(update_id_));
    its_offset += sizeof(update_id_);
    std::memcpy(&uid_, &_buffer[its_offset], sizeof(uid_));
    its_offset += sizeof(uid_);
    std::memcpy(&gid_, &_buffer[its_offset], sizeof(gid_));
}

uint32_t
remove_security_policy_command::get_update_id() const {

    return update_id_;
}

void
remove_security_policy_command::set_update_id(uint32_t _update_id) {

    update_id_ = _update_id;
}


uid_t
remove_security_policy_command::get_uid() const {

    return uid_;
}

void
remove_security_policy_command::set_uid(uid_t _uid) {

    uid_ = _uid;
}

gid_t
remove_security_policy_command::get_gid() const {

    return gid_;
}

void
remove_security_policy_command::set_gid(gid_t _gid) {

    gid_ = _gid;
}

} // namespace protocol
} // namespace vsomeip
