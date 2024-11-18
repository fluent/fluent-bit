// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/internal/logger.hpp>
#include "debounce_frequency_test_service.hpp"

uint64_t
elapsedMilliseconds(const std::chrono::time_point<std::chrono::system_clock>& _start_time) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now()
                                                                 - _start_time)
            .count();
}

void test_service::on_start(const std::shared_ptr<vsomeip::message> /*&_message*/) {
    std::unique_lock<std::mutex> lk(mutex);
    received_message = true;
    condition_wait_start.notify_one();
}

void test_service::on_stop(const std::shared_ptr<vsomeip::message> /*&_message*/) {
    VSOMEIP_INFO << "service: " << __func__ << ": Received a STOP command.";
}

test_service::test_service(const char* app_name_, const char* app_id_) :
    vsomeip_utilities::base_vsip_app(app_name_, app_id_) {
    _app->register_message_handler(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_START_METHOD,
                                   std::bind(&test_service::on_start, this, std::placeholders::_1));
    _app->register_message_handler(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_STOP_METHOD,
                                   std::bind(&test_service::on_stop, this, std::placeholders::_1));
    _app->offer_event(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT, {DEBOUNCE_EVENTGROUP},
                      vsomeip::event_type_e::ET_FIELD, std::chrono::milliseconds::zero(), false,
                      true, nullptr, vsomeip::reliability_type_e::RT_UNRELIABLE);
    _app->offer_event(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, {DEBOUNCE_EVENTGROUP},
                      vsomeip::event_type_e::ET_FIELD, std::chrono::milliseconds::zero(), false,
                      true, nullptr, vsomeip::reliability_type_e::RT_UNRELIABLE);
    _app->offer_service(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_MAJOR, DEBOUNCE_MINOR);
}

// Send the debounce events with different frequencies, but configured with the same debounce time
void test_service::send_messages() {
    std::unique_lock<std::mutex> lk(mutex);
    if (condition_wait_start.wait_for(lk, std::chrono::milliseconds(2000),
                                      [=] { return received_message; })) {

        VSOMEIP_INFO << "service: " << __func__ << ": Starting test ";
        start_time = std::chrono::system_clock::now();
        uint8_t i = 0;
        while (elapsedMilliseconds(start_time) < 3000) {

            if (elapsedMilliseconds(start_time) % 30 == 0) {
                auto its_payload = vsomeip::runtime::get()->create_payload();
                its_payload->set_data({0x00, 0x02, 0x03, 0x04, 0x05, 0x06, i++});

                _app->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT, its_payload);
                event_1_sent_messages = true;
            }

            if (elapsedMilliseconds(start_time) % 2 == 0) {
                auto its_payload = vsomeip::runtime::get()->create_payload();
                its_payload->set_data({0x00, 0x02, 0x03, 0x04, 0x05, 0x06, i++});
                _app->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);
                event_2_sent_messages = true;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}

bool test_service::was_event_1_sent() {
    return event_1_sent_messages;
}

bool test_service::was_event_2_sent() {
    return event_2_sent_messages;
}

TEST(debounce_frequency_test, server) {
    test_service debounce_server("debounce_frequency_test_service", "DFTS");
    debounce_server.send_messages();

    EXPECT_TRUE(debounce_server.was_event_1_sent()) << "Event 1 was not sent by the service";
    EXPECT_TRUE(debounce_server.was_event_2_sent()) << "Event 2 was not sent by the service";
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
