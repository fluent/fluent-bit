// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PROTOCOL_UPDATE_SECURITY_POLICY_COMMAND_HPP_
#define VSOMEIP_V3_PROTOCOL_UPDATE_SECURITY_POLICY_COMMAND_HPP_

#include <memory>

#include "command.hpp"

namespace vsomeip_v3 {

struct policy;

namespace protocol {

class update_security_policy_command
    : public command {
public:
    update_security_policy_command(bool _is_internal = false);

    void serialize(std::vector<byte_t> &_buffer, error_e &_error) const;
    void deserialize(const std::vector<byte_t> &_buffer, error_e &_error);

    // specific
    uint32_t get_update_id() const;
    void set_update_id(uint32_t _update_id);

    std::shared_ptr<policy> get_policy() const;
    void set_policy(const std::shared_ptr<policy> &_policy);

private:
    uint32_t update_id_;
    std::shared_ptr<policy> policy_;
};

} // namespace protocol
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PROTOCOL_UPDATE_SECURITY_POLICY_COMMAND_HPP_
