// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <future>
#include <gtest/gtest.h>
#include <thread>
#include <vsomeip/internal/logger.hpp>
#include <vsomeip/vsomeip.hpp>

namespace cyclic_event_test {

// Unique identifier of the test service.
constexpr vsomeip::service_t SERVICE_ID = 0x1111;

// Unique identifier of the test service instance.
constexpr vsomeip::instance_t INSTANCE_ID = 0x0001;

// Major version of the test service interface.
constexpr vsomeip::major_version_t MAJOR_VERSION = 0x1;

// Minor version of the test service interface.
constexpr vsomeip::minor_version_t MINOR_VERSION = 0x0;

// Unique identifier of the method that triggers the shutdown of the service.
constexpr vsomeip::method_t METHOD_ID = 0x0001;

// Unique identifier of the event offered by the service.
constexpr vsomeip::event_t EVENT_ID = 0x0002;

// Unique identifier of the event group to which the event belongs.
constexpr vsomeip::eventgroup_t EVENTGROUP_ID = 0x0001;

}
