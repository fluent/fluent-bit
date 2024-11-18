// Copyright (C) 2018-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_ROUTING_FUNCTION_TYPES_HPP_
#define VSOMEIP_V3_ROUTING_FUNCTION_TYPES_HPP_

namespace vsomeip_v3 {

class remote_subscription;

typedef std::function<
    void (const std::shared_ptr<remote_subscription> &_subscription)
> remote_subscription_callback_t;

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_ROUTING_FUNCTION_TYPES_HPP_
