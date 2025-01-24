// Copyright (C) 2022 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SECURITY_HPP_
#define VSOMEIP_V3_SECURITY_HPP_

#include <functional>
#include <memory>

#include <vsomeip/export.hpp>
#include <vsomeip/vsomeip_sec.h>

#include "policy_manager_impl.hpp"

namespace vsomeip_v3 {

class VSOMEIP_IMPORT_EXPORT security {
public:
    security(std::shared_ptr<policy_manager_impl> _policy_manager);
    bool load();

    std::function<decltype(vsomeip_sec_policy_initialize)>                         initialize;
    std::function<decltype(vsomeip_sec_policy_authenticate_router)>                authenticate_router;
    std::function<decltype(vsomeip_sec_policy_is_client_allowed_to_offer)>         is_client_allowed_to_offer;
    std::function<decltype(vsomeip_sec_policy_is_client_allowed_to_request)>       is_client_allowed_to_request;
    std::function<decltype(vsomeip_sec_policy_is_client_allowed_to_access_member)> is_client_allowed_to_access_member;
    std::function<decltype(vsomeip_sec_sync_client)>                               sync_client;

private:

    decltype(vsomeip_sec_policy_initialize)                         default_initialize;
    decltype(vsomeip_sec_policy_authenticate_router)                default_authenticate_router;
    decltype(vsomeip_sec_policy_is_client_allowed_to_offer)         default_is_client_allowed_to_offer;
    decltype(vsomeip_sec_policy_is_client_allowed_to_request)       default_is_client_allowed_to_request;
    decltype(vsomeip_sec_policy_is_client_allowed_to_access_member) default_is_client_allowed_to_access_member;
    decltype(vsomeip_sec_sync_client)                               default_sync_client;

    std::shared_ptr<policy_manager_impl> policy_manager_;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SECURITY_HPP_
