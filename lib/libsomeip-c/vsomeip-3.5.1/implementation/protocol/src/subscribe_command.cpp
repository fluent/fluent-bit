// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include <vsomeip/constants.hpp>

#include "../include/subscribe_command.hpp"
#include "../../configuration/include/debounce_filter_impl.hpp"

namespace vsomeip_v3 {
namespace protocol {

subscribe_command::subscribe_command()
    : subscribe_command_base(id_e::SUBSCRIBE_ID) {
}

std::shared_ptr<debounce_filter_impl_t>
subscribe_command::get_filter() const {

    return filter_;
}

void
subscribe_command::set_filter(
        const std::shared_ptr<debounce_filter_impl_t> &_filter) {

    filter_ = _filter;
}

void
subscribe_command::serialize(std::vector<byte_t> &_buffer,
        error_e &_error) const {

    size_t its_size(COMMAND_HEADER_SIZE
            + sizeof(service_) + sizeof(instance_)
            + sizeof(eventgroup_) + sizeof(major_)
            + sizeof(event_) + sizeof(pending_id_));
    size_t its_offset(its_size);

    if (filter_) {
        its_size += sizeof(filter_->on_change_)
                + sizeof(filter_->on_change_resets_interval_)
                + sizeof(filter_->interval_)
                + (filter_->ignore_.size() * (sizeof(size_t) + sizeof(byte_t)))
                + sizeof(filter_->send_current_value_after_);
    }

    if (its_size > std::numeric_limits<command_size_t>::max()) {

        _error = error_e::ERROR_MAX_COMMAND_SIZE_EXCEEDED;
        return;
    }

    // resize buffer
    _buffer.resize(its_size);

    // set size
    size_ = static_cast<command_size_t>(its_size - COMMAND_HEADER_SIZE);

    // serialize header
    subscribe_command_base::serialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    if (filter_) {

        _buffer[its_offset] = static_cast<byte_t>(filter_->on_change_);
        its_offset += sizeof(filter_->on_change_);
        _buffer[its_offset] = static_cast<byte_t>(filter_->on_change_resets_interval_);
        its_offset += sizeof(filter_->on_change_resets_interval_);
        std::memcpy(&_buffer[its_offset], &filter_->interval_, sizeof(filter_->interval_));
        its_offset += sizeof(filter_->interval_);
        for (const auto &its_ignore : filter_->ignore_) {
            std::memcpy(&_buffer[its_offset], &its_ignore.first, sizeof(size_t));
            its_offset += sizeof(size_t);
            _buffer[its_offset] = its_ignore.second;
            its_offset += sizeof(byte_t);
        }
        _buffer[its_offset] = static_cast<byte_t>(filter_->send_current_value_after_);
        its_offset += sizeof(filter_->send_current_value_after_);
    }
}

void
subscribe_command::deserialize(const std::vector<byte_t> &_buffer,
        error_e &_error) {

    size_t its_size(COMMAND_HEADER_SIZE
            + sizeof(service_) + sizeof(instance_)
            + sizeof(eventgroup_) + sizeof(major_)
            + sizeof(event_) + sizeof(pending_id_));

    if (its_size > _buffer.size()) {

        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    // deserialize header
    command::deserialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    // deserialize subscription
    subscribe_command_base::deserialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    // deserialize filter
    size_t its_offset(its_size);
    if (_buffer.size() - its_offset
            >= sizeof(bool) + sizeof(bool) + sizeof(int64_t)) {

        filter_ = std::make_shared<debounce_filter_impl_t>();
        std::memcpy(&filter_->on_change_, &_buffer[its_offset], sizeof(filter_->on_change_));
        its_offset += sizeof(filter_->on_change_);
        std::memcpy(&filter_->on_change_resets_interval_, &_buffer[its_offset], sizeof(filter_->on_change_resets_interval_));
        its_offset += sizeof(filter_->on_change_resets_interval_);
        std::memcpy(&filter_->interval_, &_buffer[its_offset], sizeof(filter_->interval_));
        its_offset += sizeof(filter_->interval_);

        while (_buffer.size() - its_offset
                >= sizeof(size_t) + sizeof(byte_t)) {

            size_t its_key;
            byte_t its_value;

            std::memcpy(&its_key, &_buffer[its_offset], sizeof(its_key));
            if (filter_->ignore_.find(its_key) != filter_->ignore_.end()) {

                _error = error_e::ERROR_MALFORMED;
                return;
            }

            its_offset += sizeof(its_key);
            its_value = _buffer[its_offset];
            its_offset += sizeof(its_value);

            filter_->ignore_.emplace(std::make_pair(its_key, its_value));
        }

        std::memcpy(&filter_->send_current_value_after_, &_buffer[its_offset], sizeof(filter_->send_current_value_after_));
        its_offset += sizeof(filter_->send_current_value_after_);
    }
}

} // namespace protocol
} // namespace vsomeip
