// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include "../include/release_service_command.hpp"

namespace vsomeip_v3 {
namespace protocol {

release_service_command::release_service_command()
    : command(id_e::RELEASE_SERVICE_ID) {

}

void
release_service_command::serialize(std::vector<byte_t> &_buffer,
        error_e &_error) const {

    size_t its_size(COMMAND_HEADER_SIZE
                + sizeof(service::service_) + sizeof(service::instance_));

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
    std::memcpy(&_buffer[its_offset], &service_.service_, sizeof(service_.service_));
    its_offset += sizeof(service_.service_);
    std::memcpy(&_buffer[its_offset], &service_.instance_, sizeof(service_.instance_));
}

void
release_service_command::deserialize(const std::vector<byte_t> &_buffer,
        error_e &_error) {

    size_t its_size(COMMAND_HEADER_SIZE
            + sizeof(service::service_) + sizeof(service::instance_));

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
    std::memcpy(&service_.service_, &_buffer[its_offset],
            sizeof(service_.service_));
    its_offset += sizeof(service_.service_);
    std::memcpy(&service_.instance_, &_buffer[its_offset],
            sizeof(service_.instance_));
}

service_t
release_service_command::get_service() const {

    return service_.service_;
}

void
release_service_command::set_service(service_t _service) {

    service_.service_ = _service;
}

instance_t
release_service_command::get_instance() const {

    return service_.instance_;
}

void
release_service_command::set_instance(instance_t _instance) {

    service_.instance_ = _instance;
}

} // namespace protocol
} // namespace vsomeip
