// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
#ifndef VSOMEIP_V3_CFG_WATCHDOG_HPP_
#define VSOMEIP_V3_CFG_WATCHDOG_HPP_

namespace vsomeip_v3 {
namespace cfg {

struct watchdog {
    watchdog()
        : is_enabeled_(false),
          timeout_in_ms_(VSOMEIP_DEFAULT_WATCHDOG_TIMEOUT),
          missing_pongs_allowed_(VSOMEIP_DEFAULT_MAX_MISSING_PONGS) {
    }

    bool is_enabeled_;
    uint32_t timeout_in_ms_;
    uint32_t missing_pongs_allowed_;
};

} // namespace cfg
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_CFG_WATCHDOG_HPP_
