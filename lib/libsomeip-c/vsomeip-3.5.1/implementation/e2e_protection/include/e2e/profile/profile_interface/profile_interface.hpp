// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_E2E_PROFILE_INTERFACE_PROFILE_INTERFACE_HPP
#define VSOMEIP_V3_E2E_PROFILE_INTERFACE_PROFILE_INTERFACE_HPP

#include <cstdint>

namespace vsomeip_v3 {
namespace e2e {
namespace profile_interface {

typedef uint8_t check_status_t;
enum generic_check_status : check_status_t { E2E_OK, E2E_WRONG_CRC, E2E_ERROR};


class profile_interface {
public:
    virtual ~profile_interface() {}
};

} // namespace profile_interface
} // namespace e2e
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_E2E_PROFILE_INTERFACE_PROFILE_INTERFACE_HPP
