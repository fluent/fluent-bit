// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <chrono>
#include <iomanip>

#include <vsomeip/internal/logger.hpp>

#include "debounce_frequency_test_client.hpp"

// Flag the desired event availability
void test_client::on_availability(vsomeip::service_t service_, vsomeip::instance_t instance_,
                                  bool _is_available) {
    if (_is_available && service_ == DEBOUNCE_SERVICE && instance_ == DEBOUNCE_INSTANCE) {
        std::unique_lock<std::mutex> lk(mutex);
        availability = true;
        condition_availability.notify_one();
    }
}

// When a message is received, verify if it is one of the required events
void test_client::on_message(const std::shared_ptr<vsomeip::message>& _message) {
    std::stringstream s;
    s << "RECV: ";
    for (uint32_t i = 0; i < _message->get_payload()->get_length(); i++) {
        s << std::hex << std::setw(2) << std::setfill('0')
          << static_cast<int>(_message->get_payload()->get_data()[i]) << " ";
    }
    VSOMEIP_DEBUG << s.str();

    if (DEBOUNCE_SERVICE == _message->get_service() && DEBOUNCE_EVENT == _message->get_method()) {
        std::unique_lock<std::mutex> lk(event_counter_mutex);
        event_1_recv_messages++;
        return;
    }
    if (DEBOUNCE_SERVICE == _message->get_service() && DEBOUNCE_EVENT_2 == _message->get_method()) {
        std::unique_lock<std::mutex> lk(event_counter_mutex);
        event_2_recv_messages++;
        return;
    }
}

test_client::test_client(const char* app_name_, const char* app_id_) :
    vsomeip_utilities::base_vsip_app(app_name_, app_id_) {
    _app->register_availability_handler(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE,
                                        std::bind(&test_client::on_availability, this,
                                                  std::placeholders::_1, std::placeholders::_2,
                                                  std::placeholders::_3),
                                        DEBOUNCE_MAJOR, DEBOUNCE_MINOR);
    _app->register_message_handler(
            DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, vsomeip::ANY_EVENT,
            std::bind(&test_client::on_message, this, std::placeholders::_1));
    _app->request_event(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT, {DEBOUNCE_EVENTGROUP},
                        vsomeip::event_type_e::ET_FIELD,
                        vsomeip::reliability_type_e::RT_UNRELIABLE);
    _app->request_event(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2,
                        {DEBOUNCE_EVENTGROUP}, vsomeip::event_type_e::ET_FIELD,
                        vsomeip::reliability_type_e::RT_UNRELIABLE);
    _app->request_service(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_MAJOR, DEBOUNCE_MINOR);
    _app->subscribe(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENTGROUP, DEBOUNCE_MAJOR,
                    DEBOUNCE_EVENT);
    _app->subscribe(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENTGROUP, DEBOUNCE_MAJOR,
                    DEBOUNCE_EVENT_2);
}

int test_client::was_event1_recv() {
    std::unique_lock<std::mutex> lk(event_counter_mutex);

    return event_1_recv_messages;
}

int test_client::was_event2_recv() {
    std::unique_lock<std::mutex> lk(event_counter_mutex);

    return event_2_recv_messages;
}

void test_client::send_request() {
    std::unique_lock<std::mutex> lk(mutex);
    // Only send the requests when the service availability is secured
    if (condition_availability.wait_for(lk, std::chrono::milliseconds(15000),
                                        [=] { return availability; })) {

        // Trigger the test
        auto its_message = vsomeip_utilities::create_standard_vsip_request(
                DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_START_METHOD, DEBOUNCE_MAJOR,
                vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
        _app->send(its_message);
    }

    EXPECT_TRUE(availability) << "Events expected by the client were not available for 15 seconds ";

    // Wait for Server to send all the messages
    std::this_thread::sleep_for(std::chrono::seconds(10));
}

void test_client::unsubscribe_all() {
    _app->unsubscribe(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENTGROUP);
}

void test_client::stop_service() {
    auto its_message = vsomeip_utilities::create_standard_vsip_request(
            DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_STOP_METHOD, DEBOUNCE_MAJOR,
            vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
    _app->send(its_message);
}

test_client::~test_client() {
    unsubscribe_all();
    stop_service();
}

TEST(debounce_frequency_test, client) {
    test_client debounce_client("debounce_frequency_test_client", "DFTC");
    // Request the server to send the test messages
    debounce_client.send_request();

    ASSERT_EQ(debounce_client.was_event1_recv(), 1)
            << "Event 1 expected to be received once by the client, instead it was received "
            << debounce_client.was_event1_recv() << " times.";
    ASSERT_EQ(debounce_client.was_event2_recv(), 1)
            << "Event 2 expected to be received once by the client, instead it was received "
            << debounce_client.was_event2_recv() << " times.";
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
