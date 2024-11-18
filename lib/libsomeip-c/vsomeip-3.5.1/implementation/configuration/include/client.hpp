// Copyright (C) 2016-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_CFG_CLIENT_HPP
#define VSOMEIP_V3_CFG_CLIENT_HPP

#include <map>
#include <memory>
#include <set>

#include <vsomeip/primitive_types.hpp>

namespace vsomeip_v3 {
namespace cfg {

struct client {
    client() : service_(ANY_SERVICE),
            instance_(ANY_INSTANCE) {
    }

    // ports for specific service / instance
    service_t service_;
    instance_t instance_;
    std::map<bool, std::set<uint16_t> > ports_;
    std::map<bool, uint16_t> last_used_specific_client_port_;

    // client port ranges mapped to remote port ranges
    std::map<bool, std::pair<uint16_t, uint16_t> > remote_ports_;
    std::map<bool, std::pair<uint16_t, uint16_t> > client_ports_;
    std::map<bool, uint16_t> last_used_client_port_;
};

} // namespace cfg
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_CFG_CLIENT_HPP
