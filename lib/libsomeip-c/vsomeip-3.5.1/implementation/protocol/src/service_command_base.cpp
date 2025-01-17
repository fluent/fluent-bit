// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include "../include/service_command_base.hpp"

namespace vsomeip_v3 {
namespace protocol {

service_command_base::service_command_base(id_e _id)
    : command(_id) {
}

service_t
service_command_base::get_service() const {

    return service_.service_;
}

void
service_command_base::set_service(service_t _service) {

    service_.service_ = _service;
}

instance_t
service_command_base::get_instance() const {

    return service_.instance_;
}

void
service_command_base::set_instance(instance_t _instance) {

    service_.instance_ = _instance;
}

major_version_t
service_command_base::get_major() const {

    return service_.major_;
}

void
service_command_base::set_major(major_version_t _major) {

    service_.major_ = _major;
}

minor_version_t
service_command_base::get_minor() const {

    return service_.minor_;
}

void
service_command_base::set_minor(minor_version_t _minor) {

    service_.minor_ = _minor;
}

void
service_command_base::serialize(std::vector<byte_t> &_buffer,
        error_e &_error) const {

    size_t its_size(COMMAND_HEADER_SIZE
            + sizeof(service_.service_) + sizeof(service_.instance_)
            + sizeof(service_.major_) + sizeof(service_.minor_));

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
    std::memcpy(&_buffer[its_offset], &service_.service_, sizeof(service_.service_));
    its_offset += sizeof(service_.service_);
    std::memcpy(&_buffer[its_offset], &service_.instance_, sizeof(service_.instance_));
    its_offset += sizeof(service_.instance_);
    _buffer[its_offset] = service_.major_;
    its_offset += sizeof(service_.major_);
    std::memcpy(&_buffer[its_offset], &service_.minor_, sizeof(service_.minor_));
}

void
service_command_base::deserialize(const std::vector<byte_t> &_buffer,
        error_e &_error) {

    size_t its_size(COMMAND_HEADER_SIZE
            + sizeof(service_.service_) + sizeof(service_.instance_)
            + sizeof(service_.major_) + sizeof(service_.minor_));

    if (its_size > _buffer.size()) {

        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    // deserialize header
    command::deserialize(_buffer, _error);

    // deserialize payload
    size_t its_offset(COMMAND_POSITION_PAYLOAD);
    std::memcpy(&service_.service_, &_buffer[its_offset], sizeof(service_.service_));
    its_offset += sizeof(service_.service_);
    std::memcpy(&service_.instance_, &_buffer[its_offset], sizeof(service_.instance_));
    its_offset += sizeof(service_.instance_);
    service_.major_ = _buffer[its_offset];
    its_offset += sizeof(service_.major_);
    std::memcpy(&service_.minor_, &_buffer[its_offset], sizeof(service_.minor_));
}

} // namespace protocol
} // namespace vsomeip
