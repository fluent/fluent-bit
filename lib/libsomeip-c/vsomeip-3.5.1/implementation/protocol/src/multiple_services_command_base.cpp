// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include "../include/multiple_services_command_base.hpp"

namespace vsomeip_v3 {
namespace protocol {

multiple_services_command_base::multiple_services_command_base(id_e _id)
    : command(_id) {

}

void
multiple_services_command_base::serialize(std::vector<byte_t> &_buffer,
        error_e &_error) const {

    size_t its_size(COMMAND_HEADER_SIZE
            + (services_.size()
                * (sizeof(service::service_) + sizeof(service::instance_)
                        + sizeof(service::major_) + sizeof(service::minor_))));

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
    for (const auto &s : services_) {
        std::memcpy(&_buffer[its_offset], &s.service_, sizeof(s.service_));
        its_offset += sizeof(s.service_);
        std::memcpy(&_buffer[its_offset], &s.instance_, sizeof(s.instance_));
        its_offset += sizeof(s.instance_);
        _buffer[its_offset] = s.major_;
        its_offset += sizeof(s.major_);
        std::memcpy(&_buffer[its_offset], &s.minor_, sizeof(s.minor_));
        its_offset += sizeof(s.minor_);
    }
}

void
multiple_services_command_base::deserialize(const std::vector<byte_t> &_buffer,
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
    size_t its_offset(COMMAND_POSITION_PAYLOAD);
    size_t its_count = (_buffer.size() - its_offset) /
            (sizeof(service::service_) + sizeof(service::instance_)
                 + sizeof(service::major_) + sizeof(service::minor_));

    for (size_t i = 0; i < its_count; i++) {
        service its_service;

        std::memcpy(&its_service.service_, &_buffer[its_offset],
                sizeof(its_service.service_));
        its_offset += sizeof(its_service.service_);
        std::memcpy(&its_service.instance_, &_buffer[its_offset],
                sizeof(its_service.instance_));
        its_offset += sizeof(its_service.instance_);
        std::memcpy(&its_service.major_, &_buffer[its_offset],
                sizeof(its_service.major_));
        its_offset += sizeof(its_service.major_);
        std::memcpy(&its_service.minor_, &_buffer[its_offset],
                sizeof(its_service.minor_));
        its_offset += sizeof(its_service.minor_);

        services_.insert(its_service);
    }
}

std::set<service>
multiple_services_command_base::get_services() const {

    return services_;
}

void
multiple_services_command_base::set_services(const std::set<service> &_services) {

    services_ = _services;
}

void
multiple_services_command_base::add_service(const service &_service) {

    services_.insert(_service);
}


} // namespace protocol
} // namespace vsomeip
