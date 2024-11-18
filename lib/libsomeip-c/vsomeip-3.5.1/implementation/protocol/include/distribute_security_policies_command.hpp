// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PROTOCOL_DISTRIBUTE_SECURITY_POLICIES_COMMAND_HPP_
#define VSOMEIP_V3_PROTOCOL_DISTRIBUTE_SECURITY_POLICIES_COMMAND_HPP_

#include <map>
#include <memory>
#include <set>
#include <vector>

#include "command.hpp"

namespace vsomeip_v3 {

class payload;
struct policy;

namespace protocol {

class distribute_security_policies_command
    : public command {
public:
    distribute_security_policies_command();

    void serialize(std::vector<byte_t> &_buffer, error_e &_error) const;
    void deserialize(const std::vector<byte_t> &_buffer, error_e &_error);

    // specific
    std::set<std::shared_ptr<policy> > get_policies() const;

    void set_payloads(const std::map<uint32_t, std::shared_ptr<payload> > &_payloads);

private:
    std::set<std::shared_ptr<policy> > policies_;
    std::vector<byte_t> payload_;
};

} // namespace protocol
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PROTOCOL_DISTRIBUTE_SECURITY_POLICIES_COMMAND_HPP_
