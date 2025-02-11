// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include "../include/routing_info_command.hpp"

namespace vsomeip_v3 {
namespace protocol {

routing_info_command::routing_info_command()
    : command(id_e::ROUTING_INFO_ID) {

}

void
routing_info_command::serialize(std::vector<byte_t> &_buffer,
        error_e &_error) const {

    size_t its_size(COMMAND_HEADER_SIZE);
    for (const auto &e : entries_)
        its_size += e.get_size();

    // resize buffer
    _buffer.resize(its_size);

    // set size
    size_ = static_cast<command_size_t>(its_size - COMMAND_HEADER_SIZE);

    // serialize header
    command::serialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    // serialize payload
    size_t _index(COMMAND_HEADER_SIZE);
    for (const auto &e : entries_) {
        e.serialize(_buffer, _index, _error);
        if (_error != error_e::ERROR_OK) {
            _buffer.clear();
            return;
        }
    }
}

void
routing_info_command::deserialize(const std::vector<byte_t> &_buffer,
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
    size_t its_index(COMMAND_HEADER_SIZE);
    while (its_index < _buffer.size()) {

        routing_info_entry its_entry;
        its_entry.deserialize(_buffer, its_index, _error);

        if (_error == error_e::ERROR_OK)
            entries_.emplace_back(its_entry);
        else
            break;
    }
}

// specific
const std::vector<routing_info_entry> &
routing_info_command::get_entries() const {

    return entries_;
}

void
routing_info_command::set_entries(std::vector<routing_info_entry> &&_entries) {

    entries_ = std::move(_entries);
}

void
routing_info_command::add_entry(const routing_info_entry &_entry) {

    entries_.push_back(_entry);
}

} // namespace protocol
} // namespace vsomeip
