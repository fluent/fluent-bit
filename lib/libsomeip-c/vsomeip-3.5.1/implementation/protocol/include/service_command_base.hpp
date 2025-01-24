// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PROTOCOL_SERVICE_COMMAND_BASE_HPP_
#define VSOMEIP_V3_PROTOCOL_SERVICE_COMMAND_BASE_HPP_

#include "command.hpp"

namespace vsomeip_v3 {
namespace protocol {

class service_command_base
    : public command {

public:
    service_t get_service() const;
    void set_service(service_t _service);

    instance_t get_instance() const;
    void set_instance(instance_t _instance);

    major_version_t get_major() const;
    void set_major(major_version_t _major);

    minor_version_t get_minor() const;
    void set_minor(minor_version_t _minor);

    void serialize(std::vector<byte_t> &_buffer,
            error_e &_error) const;
    void deserialize(const std::vector<byte_t> &_buffer,
            error_e &_error);

protected:
    service_command_base(id_e _id);

private:
    service service_;
};

} // namespace protocol
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PROTOCOL_SERVICE_COMMAND_BASE_HPP_
