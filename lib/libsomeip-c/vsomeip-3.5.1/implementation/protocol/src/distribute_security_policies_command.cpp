// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include <vsomeip/payload.hpp>

#include "../include/distribute_security_policies_command.hpp"
#include "../../security/include/policy.hpp"

namespace vsomeip_v3 {
namespace protocol {

distribute_security_policies_command::distribute_security_policies_command()
    : command(id_e::DISTRIBUTE_SECURITY_POLICIES_ID) {
}

void
distribute_security_policies_command::serialize(std::vector<byte_t> &_buffer,
        error_e &_error) const {

    size_t its_size(COMMAND_HEADER_SIZE +
        std::min(payload_.size(), size_t(std::numeric_limits<uint32_t>::max())));

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

    // serialize (add) payload
    size_t its_offset(COMMAND_HEADER_SIZE);
    if (payload_.empty()) { // No policy data (--> set_payloads was not called)
        std::memset(&_buffer[its_offset], 0, sizeof(uint32_t));
    } else {
        std::memcpy(&_buffer[its_offset], payload_.data(), payload_.size());
    }
}

void
distribute_security_policies_command::deserialize(const std::vector<byte_t> &_buffer,
        error_e &_error) {

    if (COMMAND_HEADER_SIZE + sizeof(uint32_t) > _buffer.size()) {

        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    // deserialize header
    command::deserialize(_buffer, _error);
    if (_error != error_e::ERROR_OK)
        return;

    // deserialize payload
    size_t its_offset(COMMAND_HEADER_SIZE);
    uint32_t its_policies_count;
    std::memcpy(&its_policies_count, &_buffer[its_offset],
            sizeof(its_policies_count));
    its_offset += sizeof(its_policies_count);

    for (uint32_t i = 0; i < its_policies_count; i++) {

        uint32_t its_policy_size;

        // Check that the buffer contains the full policy size
        if (its_offset + sizeof(its_policy_size) > _buffer.size()) {

            policies_.clear();
            _error = error_e::ERROR_NOT_ENOUGH_BYTES;
            return;
        }

        std::memcpy(&its_policy_size, &_buffer[its_offset],
                sizeof(its_policy_size));
        its_offset += sizeof(its_policy_size);

        // Check that the buffer contains the full policy
        if (its_offset + its_policy_size > _buffer.size()) {

            policies_.clear();
            _error = error_e::ERROR_NOT_ENOUGH_BYTES;
            return;
        }

        const byte_t *its_policy_data = &_buffer[its_offset];

        // set offset to the next policy
        its_offset += its_policy_size;

        auto its_policy = std::make_shared<policy>();
        if (its_policy_size == 0
                || !its_policy->deserialize(its_policy_data, its_policy_size)) {

            _error = error_e::ERROR_UNKNOWN;
            policies_.clear();
            return;
        }

        policies_.insert(its_policy);
    }
}

std::set<std::shared_ptr<policy> >
distribute_security_policies_command::get_policies() const {

    return policies_;
}

void
distribute_security_policies_command::set_payloads(
        const std::map<uint32_t, std::shared_ptr<payload> > &_payloads) {

    uint32_t its_count(uint32_t(_payloads.size()));
    for (uint32_t i = 0; i < sizeof(its_count); ++i) {
         payload_.push_back(
                 reinterpret_cast<const byte_t*>(&its_count)[i]);
    }

    for (const auto &its_uid_gid : _payloads) {
        // policy payload length including gid and uid
        std::uint32_t its_length(uint32_t(its_uid_gid.second->get_length()));
        for (uint32_t i = 0; i < sizeof(its_length); ++i) {
             payload_.push_back(
                     reinterpret_cast<const byte_t*>(&its_length)[i]);
        }
        // payload
        payload_.insert(payload_.end(), its_uid_gid.second->get_data(),
                its_uid_gid.second->get_data() + its_uid_gid.second->get_length());
    }
}

} // namespace protocol
} // namespace vsomeip
