// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PROTOCOL_SUBSCRIBE_COMMAND_BASE_HPP_
#define VSOMEIP_V3_PROTOCOL_SUBSCRIBE_COMMAND_BASE_HPP_

#include <memory>

#include <vsomeip/structured_types.hpp>

#include "command.hpp"

namespace vsomeip_v3 {
namespace protocol {

class subscribe_command_base
    : public command {

public:
    service_t get_service() const;
    void set_service(service_t _service);

    instance_t get_instance() const;
    void set_instance(instance_t _instance);

    eventgroup_t get_eventgroup() const;
    void set_eventgroup(eventgroup_t _eventgroup);

    major_version_t get_major() const;
    void set_major(major_version_t _major);

    event_t get_event() const;
    void set_event(event_t _event);

    pending_id_t get_pending_id() const;
    void set_pending_id(pending_id_t _pending_id);

    void serialize(std::vector<byte_t> &_buffer,
            error_e &_error) const;
    void deserialize(const std::vector<byte_t> &_buffer,
            error_e &_error);

protected:
    subscribe_command_base(id_e _id);

    service_t service_;
    instance_t instance_;
    eventgroup_t eventgroup_;
    major_version_t major_;
    event_t event_;
    pending_id_t pending_id_;
};

} // namespace protocol
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PROTOCOL_SUBSCRIBE_COMMAND_BASE_HPP_
