// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include "../include/update_security_credentials_command.hpp"

namespace vsomeip_v3 {
namespace protocol {

update_security_credentials_command::update_security_credentials_command()
    : command(id_e::UPDATE_SECURITY_CREDENTIALS_ID) {
}

void
update_security_credentials_command::serialize(std::vector<byte_t> &_buffer,
        error_e &_error) const {

    size_t its_size(COMMAND_HEADER_SIZE +
            (credentials_.size() * (sizeof(uid_t) + sizeof(gid_t))));

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
    for (const auto &c : credentials_) {
        std::memcpy(&_buffer[its_offset], &c.first, sizeof(c.first));
        its_offset += sizeof(c.first);
        std::memcpy(&_buffer[its_offset], &c.second, sizeof(c.second));
        its_offset += sizeof(c.second);
    }
}

void
update_security_credentials_command::deserialize(const std::vector<byte_t> &_buffer,
        error_e &_error) {

    if (COMMAND_HEADER_SIZE > _buffer.size()) {

        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    // deserialize header
    command::deserialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    // deserialize payload
    if (COMMAND_HEADER_SIZE + size_ > _buffer.size()) {

        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    size_t its_count(size_ / (sizeof(uid_t) + sizeof(gid_t)));
    size_t its_offset(COMMAND_HEADER_SIZE);

    uid_t its_uid;
    gid_t its_gid;
    for (size_t i = 0; i < its_count; i++) {
        std::memcpy(&its_uid, &_buffer[its_offset], sizeof(its_uid));
        its_offset += sizeof(its_uid);
        std::memcpy(&its_gid, &_buffer[its_offset], sizeof(its_gid));
        its_offset += sizeof(its_gid);

        credentials_.emplace(std::make_pair(its_uid, its_gid));
    }
}


std::set<std::pair<uid_t, gid_t> >
update_security_credentials_command::get_credentials() const {

    return credentials_;
}

void
update_security_credentials_command::set_credentials(
        const std::set<std::pair<uid_t, gid_t> > &_credentials) {

    credentials_ = _credentials;
}

} // namespace protocol
} // namespace vsomeip
