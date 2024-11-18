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

#include "applications/client.hpp"
#include "applications/service_ids.hpp"
#include "offer_stop_offer_test_helper.hpp"

TEST(test_offer_stop_offer, test_offer_stop_offer_client) {
    // Precondition 1: Service consumer application initializes correctly
    client_t service_consumer;

    ASSERT_TRUE(service_consumer.init());
    service_consumer.start();

    // Test steps:
    // > If service is available:
    //      1: send 3 request messages (service_1 via tcp, service_2 via tcp, service_3 via udp)
    //      2: validate that the requests were sent
    //      3: validate that the response was received
    //
    //      *Note_1: The value of the future itself is not relavant, only that is was set
    //      *Note_2: There can be the situation where the service goes unavailable while the
    //               requests are being sent. In that case the future is set either way, so we don't
    //               need to worry here in the test.
    //
    // > If service is not available
    //      1: do nothing
    //
    // At the end validate that the service was available, atleast once
    test_timer_t test_timer(CLIENT_UP_TIME);
    bool service_was_available = false;
    bool request_was_received = false;
    while (!test_timer.has_elapsed()) {
        if (service_consumer.is_available()) {
            service_was_available = true;

            auto request_service1_tcp =
                    service_consumer.request(true, SERVICE_ID, INSTANCE_ID, METHOD_ID);
            auto request_service2_tcp =
                    service_consumer.request(true, OTHER_SERVICE_ID, OTHER_INSTANCE_ID, METHOD_ID);
            auto request_service2_udp =
                    service_consumer.request(false, OTHER_SERVICE_ID, OTHER_INSTANCE_ID, METHOD_ID);

            // check if futures are valid
            ASSERT_TRUE(request_service1_tcp.valid());
            ASSERT_TRUE(request_service2_tcp.valid());
            ASSERT_TRUE(request_service2_udp.valid());

            // wait for responses
            request_service1_tcp.wait();
            request_service2_tcp.wait();
            request_service2_udp.wait();

            request_was_received = true;
        }
    }

    // to not get mislead if the service was never up
    EXPECT_TRUE(service_was_available);
    // to not get mislead if the request was never received
    EXPECT_TRUE(request_was_received);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
