// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/config_command.hpp"

#include <functional>
#include <limits>

namespace vsomeip_v3::protocol {

void config_command::serialize(std::vector<byte_t>& _buffer, error_e& _error) const {
    size_t size = COMMAND_HEADER_SIZE;
    for (const auto& [key, value] : configs_) {
        size += sizeof(std::uint32_t) * 2;
        size += key.size();
        size += value.size();
    }
    if (size > std::numeric_limits<command_size_t>::max()) {
        _error = error_e::ERROR_MAX_COMMAND_SIZE_EXCEEDED;
        return;
    }

    _buffer.resize(size);
    size_ = static_cast<command_size_t>(size - COMMAND_HEADER_SIZE);
    command::serialize(_buffer, _error);
    if (_error != error_e::ERROR_OK) {
        return;
    }

    size_t write_position(COMMAND_POSITION_PAYLOAD);
    for (const auto& [key, value] : configs_) {
        auto key_size = static_cast<std::uint32_t>(key.size());
        std::memcpy(&_buffer[write_position], &key_size, sizeof(std::uint32_t));
        write_position += sizeof(std::uint32_t);

        std::memcpy(&_buffer[write_position], key.data(), key.length());
        write_position += key_size;

        auto value_size = static_cast<std::uint32_t>(value.size());
        std::memcpy(&_buffer[write_position], &value_size, sizeof(std::uint32_t));
        write_position += sizeof(std::uint32_t);

        std::memcpy(&_buffer[write_position], value.data(), value.length());
        write_position += value_size;
    }
    _error = error_e::ERROR_OK;
}

void config_command::deserialize(const std::vector<byte_t>& _buffer, error_e& _error) {
    if (_buffer.size() < COMMAND_HEADER_SIZE) {
        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }
    command::deserialize(_buffer, _error);
    if (_error != error_e::ERROR_OK) {
        return;
    }
    if (get_version() != 0) {
        _error = error_e::ERROR_UNKNOWN;
        return;
    }
    std::size_t remaining = size_;
    if (_buffer.size() < remaining) {
        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }
    size_t read_position(COMMAND_POSITION_PAYLOAD);
    std::function<std::string(bool&)> read = [&_buffer, &read_position, &remaining](bool& failed) {
        if (remaining < sizeof(std::uint32_t)) {
            failed = true;
            return std::string("");
        }
        size_t size = 0;
        std::memcpy(&size, &_buffer[read_position], sizeof(std::uint32_t));
        remaining -= sizeof(std::uint32_t);
        read_position += sizeof(std::uint32_t);
        if (remaining < size) {
            failed = true;
            return std::string("");
        }
        std::string value;
        value.assign(&_buffer[read_position], &_buffer[read_position + size]);
        remaining -= size;
        read_position += size;
        return value;
    };
    while (remaining > 0) {
        bool failed = false;
        std::string key = read(failed);
        if (failed) {
            _error = error_e::ERROR_NOT_ENOUGH_BYTES;
            return;
        }
        std::string value = read(failed);
        if (failed) {
            _error = error_e::ERROR_NOT_ENOUGH_BYTES;
            return;
        }
        configs_[key] = value;
    }
    _error = error_e::ERROR_OK;
}

void config_command::insert(const std::string& _key, const std::string&& _value) {
    configs_.insert_or_assign(_key, std::move(_value));
}

bool config_command::contains(const std::string& _key) const {
    return configs_.find(_key) != configs_.end();
}

const std::string& config_command::at(const std::string& _key) const {
    return configs_.at(_key);
}

const std::map<std::string, std::string, std::less<>>& config_command::configs() const {
    return configs_;
}

} // namespace vsomeip_v3::protocol
