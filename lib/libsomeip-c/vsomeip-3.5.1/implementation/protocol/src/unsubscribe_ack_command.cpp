// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include <vsomeip/constants.hpp>

#include "../include/unsubscribe_ack_command.hpp"

namespace vsomeip_v3 {
namespace protocol {

unsubscribe_ack_command::unsubscribe_ack_command()
    : command(id_e::UNSUBSCRIBE_ACK_ID),
      service_(ANY_SERVICE),
      instance_(ANY_INSTANCE),
      eventgroup_(0),
      pending_id_(0) {
}

service_t
unsubscribe_ack_command::get_service() const {

    return service_;
}

void
unsubscribe_ack_command::set_service(service_t _service) {

    service_ = _service;
}

instance_t
unsubscribe_ack_command::get_instance() const {

    return instance_;
}

void
unsubscribe_ack_command::set_instance(instance_t _instance) {

    instance_ = _instance;
}

eventgroup_t
unsubscribe_ack_command::get_eventgroup() const {

    return eventgroup_;
}

void
unsubscribe_ack_command::set_eventgroup(eventgroup_t _eventgroup) {

    eventgroup_ = _eventgroup;
}

pending_id_t
unsubscribe_ack_command::get_pending_id() const {

    return pending_id_;
}

void
unsubscribe_ack_command::set_pending_id(pending_id_t _pending_id) {

    pending_id_ = _pending_id;
}

void
unsubscribe_ack_command::serialize(std::vector<byte_t> &_buffer,
        error_e &_error) const {

    size_t its_size(COMMAND_HEADER_SIZE
            + sizeof(service_) + sizeof(instance_)
            + sizeof(eventgroup_) + sizeof(pending_id_));

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

    // payload
    size_t its_offset(COMMAND_HEADER_SIZE);
    std::memcpy(&_buffer[its_offset], &service_, sizeof(service_));
    its_offset += sizeof(service_);
    std::memcpy(&_buffer[its_offset], &instance_, sizeof(instance_));
    its_offset += sizeof(instance_);
    std::memcpy(&_buffer[its_offset], &eventgroup_, sizeof(eventgroup_));
    its_offset += sizeof(eventgroup_);
    std::memcpy(&_buffer[its_offset], &pending_id_, sizeof(pending_id_));
}

void
unsubscribe_ack_command::deserialize(const std::vector<byte_t> &_buffer,
        error_e &_error) {

    size_t its_size(COMMAND_HEADER_SIZE
            + sizeof(service_) + sizeof(instance_)
            + sizeof(eventgroup_) + sizeof(pending_id_));

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
    std::memcpy(&eventgroup_, &_buffer[its_offset], sizeof(eventgroup_));
    its_offset += sizeof(eventgroup_);
    std::memcpy(&pending_id_, &_buffer[its_offset], sizeof(pending_id_));

}

} // namespace protocol
} // namespace vsomeip
