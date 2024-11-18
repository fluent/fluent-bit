// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "cyclic_event_test_globals.hpp"

using namespace cyclic_event_test;

TEST(CyclicEventTest, ClientReceivesMultipleEvents) {
    // Initialize the runtime.
    auto runtime = vsomeip::runtime::get();
    ASSERT_TRUE(runtime) << "Should create a vsomeip runtime.";

    // Initialize the application.
    auto application = runtime->create_application("client-sample");
    ASSERT_TRUE(application) << "Should create a vsomeip application.";
    ASSERT_TRUE(application->init()) << "Should initialize application.";

    // Create a promise to shutdown the service.
    std::promise<bool> shutdown_promise;
    auto shutdown_future = shutdown_promise.get_future();

    // Track amount of notifications that were received.
    std::atomic_uint8_t notification_count {0};

    // Handle an event notification.
    application->register_message_handler(
            SERVICE_ID, INSTANCE_ID, EVENT_ID,
            [runtime, application,
             &notification_count](const std::shared_ptr<vsomeip::message> /* message */) {
                VSOMEIP_INFO << "Received event notification.";

                constexpr std::uint8_t MIN_NOTIFICATION_COUNT = 3;
                if ((notification_count += 1) != MIN_NOTIFICATION_COUNT) {
                    return;
                }

                auto shutdown_request = runtime->create_request(false);
                shutdown_request->set_service(SERVICE_ID);
                shutdown_request->set_instance(INSTANCE_ID);
                shutdown_request->set_method(METHOD_ID);
                shutdown_request->set_interface_version(MAJOR_VERSION);
                application->send(shutdown_request);
            });

    // Handle shutdown response.
    application->register_message_handler(
            SERVICE_ID, INSTANCE_ID, METHOD_ID,
            [&shutdown_promise](const std::shared_ptr<vsomeip::message> /* message */) {
                VSOMEIP_INFO << "Received shutdown response.";
                shutdown_promise.set_value(true);
            });

    // Request the test service.
    application->request_service(SERVICE_ID, INSTANCE_ID, MAJOR_VERSION, MINOR_VERSION);
    application->request_event(SERVICE_ID, INSTANCE_ID, EVENT_ID, {EVENTGROUP_ID});

    // Subscribe to the test service when it becomes available.
    application->register_availability_handler(
            SERVICE_ID, INSTANCE_ID,
            [application](vsomeip::service_t /* service */, vsomeip::instance_t /* instance */,
                          bool is_available) {
                if (is_available) {
                    application->subscribe(SERVICE_ID, INSTANCE_ID, EVENTGROUP_ID, MAJOR_VERSION);
                }
            },
            MAJOR_VERSION, MINOR_VERSION);

    // Start the vsomeip application.
    std::thread worker_thread([application] { application->start(); });

    // Wait for the shutdown call.
    shutdown_future.wait();
    application->stop();

    // Clean up worker thread.
    if (worker_thread.joinable()) {
        worker_thread.join();
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
