// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include "../include/unregister_event_command.hpp"

namespace vsomeip_v3 {
namespace protocol {

unregister_event_command::unregister_event_command()
        : command(id_e::UNREGISTER_EVENT_ID),
          service_(ANY_SERVICE),
          instance_(ANY_INSTANCE),
          event_(ANY_EVENT),
          is_provided_(false) {
}

service_t
unregister_event_command::get_service() const {

    return service_;
}

void
unregister_event_command::set_service(service_t _service) {

    service_ = _service;
}

instance_t
unregister_event_command::get_instance() const {

    return instance_;
}

void
unregister_event_command::set_instance(instance_t _instance) {

    instance_ = _instance;
}

event_t
unregister_event_command::get_event() const {

    return event_;
}

void
unregister_event_command::set_event(event_t _event) {

    event_ = _event;
}


bool
unregister_event_command::is_provided() const {

    return is_provided_;
}

void
unregister_event_command::set_provided(bool _is_provided) {

    is_provided_ = _is_provided;
}

void
unregister_event_command::serialize(std::vector<byte_t> &_buffer, error_e &_error) const {

    size_t its_size(COMMAND_HEADER_SIZE
            + sizeof(service_) + sizeof(instance_)
            + sizeof(event_) + sizeof(is_provided_));

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
    std::memcpy(&_buffer[its_offset], &service_, sizeof(service_));
    its_offset += sizeof(service_);
    std::memcpy(&_buffer[its_offset], &instance_, sizeof(instance_));
    its_offset += sizeof(instance_);
    std::memcpy(&_buffer[its_offset], &event_, sizeof(event_));
    its_offset += sizeof(event_);
    _buffer[its_offset] = static_cast<byte_t>(is_provided_);
}

void
unregister_event_command::deserialize(const std::vector<byte_t> &_buffer, error_e &_error) {

    size_t its_size(COMMAND_HEADER_SIZE
            + sizeof(service_) + sizeof(instance_)
            + sizeof(event_) + sizeof(is_provided_));

    if (its_size > _buffer.size()) {

        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    // deserialize header
    command::deserialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    // payload
    size_t its_offset(COMMAND_HEADER_SIZE);
    std::memcpy(&service_, &_buffer[its_offset], sizeof(service_));
    its_offset += sizeof(service_);
    std::memcpy(&instance_, &_buffer[its_offset], sizeof(instance_));
    its_offset += sizeof(instance_);
    std::memcpy(&event_, &_buffer[its_offset], sizeof(event_));
    its_offset += sizeof(event_);
    is_provided_ = static_cast<bool>(_buffer[its_offset]);
}

} // namespace protocol
} // namespace vsomeip_v3
