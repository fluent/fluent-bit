// Copyright (C) 2021-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PROTOCOL_COMMAND_HPP_
#define VSOMEIP_V3_PROTOCOL_COMMAND_HPP_

#include <cstring> // memcpy
#include <vector>

#include <vsomeip/primitive_types.hpp>

#include "protocol.hpp"

namespace vsomeip_v3 {
namespace protocol {

typedef uint32_t command_size_t;

class command {
public:
    inline id_e get_id() const  { return id_; }
    inline version_t get_version() const { return version_; }
    inline client_t get_client() const { return client_; }
    inline void set_client(client_t _client) { client_ = _client; }
    inline command_size_t get_size() const { return size_; }

    virtual void serialize(std::vector<byte_t> &_buffer,
            error_e &_error) const;
    virtual void deserialize(const std::vector<byte_t> &_buffer,
            error_e &_error);

protected:
    id_e id_;
    version_t version_;
    client_t client_;
    mutable command_size_t size_;

    command(id_e _id);
};

} // namespace protocol
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PROTOCOL_COMMAND_HPP_
