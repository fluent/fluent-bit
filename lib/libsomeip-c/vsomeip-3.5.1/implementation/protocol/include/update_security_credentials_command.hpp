// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PROTOCOL_UPDATE_SECURITY_CREDENTIALS_COMMAND_HPP_
#define VSOMEIP_V3_PROTOCOL_UPDATE_SECURITY_CREDENTIALS_COMMAND_HPP_

#include <set>

#include "command.hpp"

namespace vsomeip_v3 {

struct policy;

namespace protocol {

class update_security_credentials_command
    : public command {
public:
    update_security_credentials_command();

    void serialize(std::vector<byte_t> &_buffer, error_e &_error) const;
    void deserialize(const std::vector<byte_t> &_buffer, error_e &_error);

    // specific
    std::set<std::pair<uid_t, gid_t> > get_credentials() const;
    void set_credentials(
            const std::set<std::pair<uid_t, gid_t> > &_credentials);

private:
    std::set<std::pair<uid_t, gid_t> > credentials_;
};

} // namespace protocol
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PROTOCOL_UPDATE_SECURITY_CREDENTIALS_COMMAND_HPP_
