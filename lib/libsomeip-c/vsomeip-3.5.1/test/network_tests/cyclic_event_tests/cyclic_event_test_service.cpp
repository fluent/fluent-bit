// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "cyclic_event_test_globals.hpp"

using namespace cyclic_event_test;

TEST(CyclicEventTest, ServiceNotifiesClient) {
    // Initialize the runtime.
    auto runtime = vsomeip::runtime::get();
    ASSERT_TRUE(runtime) << "Should create a vsomeip runtime.";

    // Initialize the application.
    auto application = runtime->create_application("service-sample");
    ASSERT_TRUE(application) << "Should create a vsomeip application.";
    ASSERT_TRUE(application->init()) << "Should initialize application.";

    // Create a promise to shutdown the service.
    std::promise<bool> shutdown_promise;
    auto shutdown_future = shutdown_promise.get_future();

    // Handle a shutdown method call.
    application->register_message_handler(SERVICE_ID, INSTANCE_ID, METHOD_ID,
                                          [runtime, application, &shutdown_promise](
                                                  const std::shared_ptr<vsomeip::message> message) {
                                              VSOMEIP_INFO << "Received shutdown request.";

                                              auto response = runtime->create_response(message);
                                              application->send(response);

                                              shutdown_promise.set_value(true);
                                          });

    // Offer the test service.
    application->offer_service(SERVICE_ID, INSTANCE_ID, MAJOR_VERSION, MINOR_VERSION);
    application->offer_event(SERVICE_ID, INSTANCE_ID, EVENT_ID, {EVENTGROUP_ID},
                             vsomeip_v3::event_type_e::ET_FIELD);

    // Start the vsomeip application.
    std::thread worker_thread([application] { application->start(); });

    // Set the value of the event field.
    auto payload = runtime->create_payload({0x01});
    application->notify(SERVICE_ID, INSTANCE_ID, EVENT_ID, payload);

    // Wait for the shutdown call.
    shutdown_future.wait();

    // Give the client a chance to exit cleanly.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
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
