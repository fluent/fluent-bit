// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <future>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>
#include <common/vsomeip_app_utilities.hpp>
#include <common/test_timer.hpp>

#include <gtest/gtest.h>

#include "applications/service.hpp"
#include "offer_stop_offer_test_helper.hpp"

TEST(test_offer_stop_offer, test_offer_stop_offer_service) {
    // Precondition 1: Service provider application initializes correctly
    service_t service_provider;

    ASSERT_TRUE(service_provider.init());
    service_provider.start();

    // Precondition 2: routingmanagerd is able to route
    auto routing_availability_check = service_provider.offer();
    ASSERT_TRUE(routing_availability_check.valid());
    routing_availability_check.wait();
    ASSERT_TRUE(routing_availability_check.get()) << "routingmanagerd was not ready in time!";

    test_timer_t test_timer(SERVICE_UP_TIME);

    // Test steps:
    // 1: STOP_OFFERING the services for SERVICE_STOP_OFFER_TIME
    // 2: validate that the services are not available
    // 3: OFFER the services again
    // 4: validate that the services are available
    // Repeate above steps for SERVICE_UP_TIME
    while (!test_timer.has_elapsed()) {

        auto stop_offer_confirmation = service_provider.stop_offer();
        // Wait confirmation that all services have became unavailable
        ASSERT_TRUE(stop_offer_confirmation.valid());
        stop_offer_confirmation.wait();
        ASSERT_FALSE(stop_offer_confirmation.get()) << "stop_offer was not confirmed in time!";

        std::this_thread::sleep_for(SERVICE_STOP_OFFER_TIME);

        auto offer_confirmation = service_provider.offer();
        // Wait confirmation that all services have became available
        ASSERT_TRUE(offer_confirmation.valid());
        offer_confirmation.wait();
        ASSERT_TRUE(offer_confirmation.get()) << "offer was not confirmed in time!";

        std::this_thread::sleep_for(SERVICE_OFFER_TIME);
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
