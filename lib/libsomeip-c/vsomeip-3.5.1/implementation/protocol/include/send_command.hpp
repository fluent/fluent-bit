// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PROTOCOL_SEND_COMMAND_HPP_
#define VSOMEIP_V3_PROTOCOL_SEND_COMMAND_HPP_

#include "command.hpp"

namespace vsomeip_v3 {
namespace protocol {

class send_command
    : public command {
public:
    send_command(id_e _id);

    void serialize(std::vector<byte_t> &_buffer,
            error_e &_error) const;
    void deserialize(const std::vector<byte_t> &_buffer,
            error_e &_error);

    instance_t get_instance() const;
    void set_instance(instance_t _instance);

    bool is_reliable() const;
    void set_reliable(bool _is_reliable);

    uint8_t get_status() const;
    void set_status(uint8_t _status);

    client_t get_target() const;
    void set_target(client_t _target);

    // TODO: Optimize this as the vector might be huge!
    std::vector<byte_t> get_message() const;
    void set_message(const std::vector<byte_t> &_message);

private:

    instance_t instance_;
    bool is_reliable_;
    uint8_t status_; // TODO: DO WE REALLY NEED THIS?
    client_t target_;
    std::vector<byte_t> message_;
};

} // namespace protocol
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PROTOCOL_BASIC_COMMAND_HPP_
