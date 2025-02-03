// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PROTOCOL_REMOVE_SECURITY_POLICY_COMMAND_HPP_
#define VSOMEIP_V3_PROTOCOL_REMOVE_SECURITY_POLICY_COMMAND_HPP_

#include "command.hpp"

namespace vsomeip_v3 {
namespace protocol {

class remove_security_policy_command
    : public command {
public:
    remove_security_policy_command();

    void serialize(std::vector<byte_t> &_buffer, error_e &_error) const;
    void deserialize(const std::vector<byte_t> &_buffer, error_e &_error);

    // specific
    uint32_t get_update_id() const;
    void set_update_id(uint32_t _update_id);

    uid_t get_uid() const;
    void set_uid(uid_t _uid);

    gid_t get_gid() const;
    void set_gid(gid_t _gid);

private:
    uint32_t update_id_;
    uid_t uid_;
    gid_t gid_;
};

} // namespace protocol
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PROTOCOL_REMOVE_SECURITY_POLICY_COMMAND_HPP_
