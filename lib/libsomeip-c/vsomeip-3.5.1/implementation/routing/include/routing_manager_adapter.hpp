// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_ROUTING_MANAGER_ADAPTER_
#define VSOMEIP_V3_ROUTING_MANAGER_ADAPTER_

namespace vsomeip_v3 {

class routing_manager;

class routing_manager_adapter {
public:
    virtual ~routing_manager_adapter() {
    }

    virtual routing_manager * get_manager() = 0;
    virtual void process_command(const byte_t *_data, length_t _length) = 0;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_ROUTING_MANAGER_ADAPTER_HPP_
