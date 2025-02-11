// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef TEST_OFFER_STOP_OFFER_HELPER_HPP
#define TEST_OFFER_STOP_OFFER_HELPER_HPP

#include <chrono>

/// @brief Time for which the service application is active
constexpr auto SERVICE_UP_TIME = std::chrono::seconds(9);

/// @brief Time for which the service application is offering the services and responding to
///        requests
constexpr auto SERVICE_OFFER_TIME = std::chrono::milliseconds(500);

/// @brief Time for which the service application stops offering the services
constexpr auto SERVICE_STOP_OFFER_TIME = std::chrono::milliseconds(2);

/// @brief Time for which the client application is active
constexpr auto CLIENT_UP_TIME = std::chrono::seconds(10);

#endif // TEST_OFFER_STOP_OFFER_HELPER_HPP
