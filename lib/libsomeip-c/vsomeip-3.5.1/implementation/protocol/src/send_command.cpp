// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include "../include/send_command.hpp"

namespace vsomeip_v3 {
namespace protocol {

send_command::send_command(id_e _id)
    : command(_id) {
}

instance_t
send_command::get_instance() const {

    return instance_;
}

void
send_command::set_instance(instance_t _instance) {

    instance_ = _instance;
}

bool
send_command::is_reliable() const {

    return is_reliable_;
}

void
send_command::set_reliable(bool _is_reliable) {

    is_reliable_ = _is_reliable;
}

uint8_t
send_command::get_status() const {

    return status_;
}

void
send_command::set_status(uint8_t _status) {

    status_ = _status;
}

client_t
send_command::get_target() const {

    return target_;
}

void
send_command::set_target(client_t _target) {

    target_ = _target;
}

std::vector<byte_t>
send_command::get_message() const {

    return message_;
}

void
send_command::set_message(const std::vector<byte_t> &_message) {

    message_ = std::move(_message);
}

void
send_command::serialize(std::vector<byte_t> &_buffer,
        error_e &_error) const {

    size_t its_size(COMMAND_HEADER_SIZE + sizeof(instance_)
            + sizeof(is_reliable_) + sizeof(status_)
            + sizeof(target_) + message_.size());

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
    size_t its_offset(COMMAND_POSITION_PAYLOAD);
    std::memcpy(&_buffer[its_offset], &instance_, sizeof(instance_));
    its_offset += sizeof(instance_);
    _buffer[its_offset] = static_cast<byte_t>(is_reliable_);
    its_offset += sizeof(is_reliable_);
    _buffer[its_offset] = static_cast<byte_t>(status_);
    its_offset += sizeof(status_);
    std::memcpy(&_buffer[its_offset], &target_, sizeof(target_));
    its_offset += sizeof(target_);
    std::memcpy(&_buffer[its_offset], &message_[0], message_.size());
}

void
send_command::deserialize(const std::vector<byte_t> &_buffer,
        error_e &_error) {

    size_t its_size(COMMAND_HEADER_SIZE + sizeof(instance_)
                + sizeof(is_reliable_) + sizeof(status_)
                + sizeof(target_));

    if (its_size > _buffer.size()) {

        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    // deserialize header
    command::deserialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    // deserialize payload
    size_t its_offset(COMMAND_POSITION_PAYLOAD);
    std::memcpy(&instance_, &_buffer[its_offset], sizeof(instance_));
    its_offset += sizeof(instance_);
    is_reliable_ = static_cast<bool>(_buffer[its_offset]);
    its_offset += sizeof(is_reliable_);
    status_ = static_cast<uint8_t>(_buffer[its_offset]);
    its_offset += sizeof(status_);
    std::memcpy(&target_, &_buffer[its_offset], sizeof(target_));
    its_offset += sizeof(target_);
    message_.resize(_buffer.size() - its_offset);
    std::memcpy(&message_[0], &_buffer[its_offset], message_.size());
}

} // namespace protocol
} // namespace vsomeip
