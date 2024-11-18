// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_ERROR_HPP
#define VSOMEIP_ERROR_HPP

#include "../../compat/vsomeip/primitive_types.hpp"

namespace vsomeip {

enum class error_code_e : uint8_t {
    CONFIGURATION_MISSING,
    PORT_CONFIGURATION_MISSING,
    CLIENT_ENDPOINT_CREATION_FAILED,
    SERVER_ENDPOINT_CREATION_FAILED,
    SERVICE_PROPERTY_MISMATCH
};

extern const char *ERROR_INFO[];

} // namespace vsomeip

#endif // VSOMEIP_ERROR_HPP

