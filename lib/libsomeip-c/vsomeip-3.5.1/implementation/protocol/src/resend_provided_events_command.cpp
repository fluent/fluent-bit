// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include "../include/resend_provided_events_command.hpp"

namespace vsomeip_v3 {
namespace protocol {

resend_provided_events_command::resend_provided_events_command()
    : command(id_e::RESEND_PROVIDED_EVENTS_ID) {

}

void
resend_provided_events_command::serialize(std::vector<byte_t> &_buffer,
        error_e &_error) const {

    size_t its_size(COMMAND_HEADER_SIZE + sizeof(remote_offer_id_));

    if (its_size > std::numeric_limits<command_size_t>::max()) {

        _error = error_e::ERROR_MAX_COMMAND_SIZE_EXCEEDED;
        return;
    }

    // resize buffer
    _buffer.resize(its_size);

    // set size
    size_ = static_cast<command_size_t>(sizeof(remote_offer_id_));

    // serialize header
    command::serialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    // serialize payload
    std::memcpy(&_buffer[COMMAND_POSITION_PAYLOAD], &remote_offer_id_,
            sizeof(remote_offer_id_));
}

void
resend_provided_events_command::deserialize(const std::vector<byte_t> &_buffer,
        error_e &_error) {

    if (COMMAND_HEADER_SIZE + sizeof(remote_offer_id_) > _buffer.size()) {

        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    // deserialize header
    command::deserialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    // deserialize payload
    std::memcpy(&remote_offer_id_, &_buffer[COMMAND_POSITION_PAYLOAD],
            sizeof(remote_offer_id_));
}

pending_remote_offer_id_t
resend_provided_events_command::get_remote_offer_id() const {

    return remote_offer_id_;
}

void
resend_provided_events_command::set_remote_offer_id(
        pending_remote_offer_id_t _remote_offer_id) {

    remote_offer_id_ = _remote_offer_id;
}

} // namespace protocol
} // namespace vsomeip
