// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_SERVICE_IDS_HPP
#define VSOMEIP_SERVICE_IDS_HPP

#include <vsomeip/vsomeip.hpp>

/// @brief First service id
constexpr vsomeip::service_t SERVICE_ID = 0x1234;

/// @brief First service instance id
constexpr vsomeip::instance_t INSTANCE_ID = 0x5678;

/// @brief First service method id
constexpr vsomeip::method_t METHOD_ID = 0x0421;

/// @brief Second service id
constexpr vsomeip::service_t OTHER_SERVICE_ID = 0x1235;

/// @brief Second service instance id
constexpr vsomeip::instance_t OTHER_INSTANCE_ID = 0x5678;

/// @brief Second service method id
constexpr vsomeip::method_t OTHER_METHOD_ID = 0x0421;

/// @brief Both services event id
constexpr vsomeip::event_t EVENT_ID = 0x8778;

/// @brief Both services eventgroup id
constexpr vsomeip::eventgroup_t EVENTGROUP_ID = 0x4465;


#endif // VSOMEIP_EXAMPLES_IDS_HPP
