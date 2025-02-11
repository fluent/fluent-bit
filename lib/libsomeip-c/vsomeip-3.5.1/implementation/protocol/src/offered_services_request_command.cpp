// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include "../include/offered_services_request_command.hpp"

namespace vsomeip_v3 {
namespace protocol {

offered_services_request_command::offered_services_request_command()
    : command(id_e::OFFERED_SERVICES_REQUEST_ID) {
}

void
offered_services_request_command::serialize(std::vector<byte_t> &_buffer,
        error_e &_error) const {

    size_t its_size(COMMAND_HEADER_SIZE + sizeof(offer_type_));

    if (its_size > std::numeric_limits<command_size_t>::max()) {

        _error = error_e::ERROR_MAX_COMMAND_SIZE_EXCEEDED;
        return;
    }

    // resize buffer
    _buffer.resize(its_size);

    // set size
    size_ = static_cast<command_size_t>(sizeof(offer_type_));

    // serialize header
    command::serialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    // serialize payload
    std::memcpy(&_buffer[COMMAND_POSITION_PAYLOAD], &offer_type_,
            sizeof(offer_type_));
}

void
offered_services_request_command::deserialize(const std::vector<byte_t> &_buffer,
        error_e &_error) {

    if (COMMAND_HEADER_SIZE + sizeof(offer_type_) > _buffer.size()) {

        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    // deserialize header
    command::deserialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    // deserialize payload
    std::memcpy(&offer_type_, &_buffer[COMMAND_POSITION_PAYLOAD],
            sizeof(offer_type_));
}

offer_type_e
offered_services_request_command::get_offer_type() const {

    return offer_type_;
}

void
offered_services_request_command::set_offer_type(offer_type_e _offer_type) {

    offer_type_ = _offer_type;
}

} // namespace protocol
} // namespace vsomeip
