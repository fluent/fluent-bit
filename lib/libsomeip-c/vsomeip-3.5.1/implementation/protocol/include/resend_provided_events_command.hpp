// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PROTOCOL_RESEND_PROVIDED_EVENTS_COMMAND_HPP_
#define VSOMEIP_V3_PROTOCOL_RESEND_PROVIDED_EVENTS_COMMAND_HPP_

#include "command.hpp"

namespace vsomeip_v3 {
namespace protocol {

class resend_provided_events_command
    : public command {
public:
    resend_provided_events_command();

    void serialize(std::vector<byte_t> &_buffer, error_e &_error) const;
    void deserialize(const std::vector<byte_t> &_buffer, error_e &_error);

    // specific
    pending_remote_offer_id_t get_remote_offer_id() const;
    void set_remote_offer_id(pending_remote_offer_id_t _remote_offer_id);

private:
    pending_remote_offer_id_t remote_offer_id_;
};

} // namespace protocol
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PROTOCOL_RESEND_PROVIDED_EVENTS_COMMAND_HPP_
