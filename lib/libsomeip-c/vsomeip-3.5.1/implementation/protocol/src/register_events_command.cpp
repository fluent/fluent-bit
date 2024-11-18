// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include "../include/register_events_command.hpp"
#include <vsomeip/internal/logger.hpp>

namespace vsomeip_v3 {
namespace protocol {

register_events_command::register_events_command()
        : command(id_e::REGISTER_EVENT_ID) {
}

bool
register_events_command::add_registration(const register_event &_register_event) {

    size_t its_size(size_ + COMMAND_HEADER_SIZE
            + sizeof(_register_event.get_service()) + sizeof(_register_event.get_instance())
            + sizeof(_register_event.get_event()) + sizeof(_register_event.get_event_type())
            + sizeof(_register_event.is_provided()) + sizeof(_register_event.get_reliability())
            + sizeof(_register_event.is_cyclic()) + sizeof(_register_event.get_num_eventgroups())
            + (_register_event.get_num_eventgroups() * sizeof(eventgroup_t) ));

    // check size
    if (its_size > std::numeric_limits<command_size_t>::max())
        return false;

    // set size
    size_ = static_cast<command_size_t>(its_size - COMMAND_HEADER_SIZE);
    registrations_.push_back(_register_event);

    return true;
}

void
register_events_command::serialize(std::vector<byte_t> &_buffer, error_e &_error) const {

    if (size_ + COMMAND_HEADER_SIZE > std::numeric_limits<command_size_t>::max()) {
        _error = error_e::ERROR_MAX_COMMAND_SIZE_EXCEEDED;
        return;
    }

    // resize buffer
    _buffer.resize(size_+COMMAND_HEADER_SIZE);

    // serialize header
    command::serialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    // serialize payload
    size_t its_offset(COMMAND_HEADER_SIZE);
    for(auto &reg : registrations_) {
        reg.serialize(_buffer, its_offset, _error);
        if (_error != error_e::ERROR_OK)
        	return;
    }
}

void
register_events_command::deserialize(const std::vector<byte_t> &_buffer, error_e &_error) {
    registrations_.clear();

    if(_buffer.size() < COMMAND_HEADER_SIZE) {
        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    // deserialize header
    command::deserialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    size_t its_offset(COMMAND_HEADER_SIZE);

    while (its_offset < _buffer.size()) {
        register_event event_command;
        event_command.deserialize(_buffer, its_offset, _error);
        if (_error != error_e::ERROR_OK)
        	return;

        registrations_.push_back(event_command);
    }
}

std::size_t
register_events_command::get_num_registrations() const {

    return registrations_.size();
}

bool
register_events_command::get_registration_at(std::size_t _position, register_event & _reg) const {

    if(_position < registrations_.size()) {
        _reg = registrations_[_position];
        return true;
    }
    return false;
}

} // namespace protocol
} // namespace vsomeip_v3
