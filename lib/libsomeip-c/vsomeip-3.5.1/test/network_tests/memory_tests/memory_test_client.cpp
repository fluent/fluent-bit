// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <chrono>
#include <iomanip>
#include <cstring>

#include <vsomeip/internal/logger.hpp>
#include "memory_test_client.hpp"

void check_memory(std::vector<std::uint64_t> &test_memory_, std::atomic<bool> &stop_checking_)
{
    while (!stop_checking_) {
        std::this_thread::sleep_for(MEMORY_CHECKER_INTERVAL);

        static const std::uint32_t its_pagesize = static_cast<std::uint32_t>(getpagesize() / 1024);

        std::FILE *its_file = std::fopen("/proc/self/statm", "r");
        if (!its_file) {
            VSOMEIP_ERROR << "check_memory: couldn't open:"
                          << std::string(std::strerror(errno));
            return;
        }
        std::uint64_t its_size(0);
        std::uint64_t its_rsssize(0);
        std::uint64_t its_sharedpages(0);
        std::uint64_t its_text(0);
        std::uint64_t its_lib(0);
        std::uint64_t its_data(0);
        std::uint64_t its_dirtypages(0);

        if (EOF
            == std::fscanf(its_file, "%lu %lu %lu %lu %lu %lu %lu", &its_size, &its_rsssize,
                           &its_sharedpages, &its_text, &its_lib, &its_data, &its_dirtypages)) {
            VSOMEIP_ERROR << "check_memory: error reading:"
                          << std::string(std::strerror(errno));
        }
        std::fclose(its_file);

        test_memory_.push_back(its_rsssize * its_pagesize);
        VSOMEIP_INFO << "logged client: "<< its_rsssize * its_pagesize;

    }
}

// Flag the desired event availability
void memory_test_client::on_availability(vsomeip::service_t service_, vsomeip::instance_t instance_,
                                         bool is_available_)
{
    if (is_available_ && service_ == MEMORY_SERVICE && instance_ == MEMORY_INSTANCE) {
        std::unique_lock<std::mutex> lk(availability_mutex);
        availability = true;
        condition_availability.notify_one();
    }
}

void memory_test_client::on_message(const std::shared_ptr<vsomeip::message> &message_)
{
    if (MEMORY_SERVICE == message_->get_service() && message_->get_method() <= MEMORY_EVENT + TEST_EVENT_NUMBER
        && message_->get_method() >= MEMORY_EVENT) {
        auto its_runtime = vsomeip::runtime::get();
        auto its_message = its_runtime->create_request(false);
        its_message->set_service(message_->get_service());
        its_message->set_instance(message_->get_instance());
        its_message->set_method(message_->get_method());
        its_message->set_interface_version(message_->get_interface_version());
        its_message->set_message_type(vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
        its_message->set_payload(message_->get_payload());
        _app->send(its_message);
        std::lock_guard<std::mutex> lk(event_counter_mutex);
        received_messages_counter++;
        sec = std::chrono::system_clock::now();
    }
}

memory_test_client::memory_test_client(const char *app_name_, const char *app_id_,
                                       std::map<vsomeip::event_t, int> map_events_)
    : vsomeip_utilities::base_vsip_app(app_name_, app_id_), map_events(map_events_)
{
    sec = std::chrono::system_clock::now();
    _app->register_availability_handler(MEMORY_SERVICE, MEMORY_INSTANCE,
                                        std::bind(&memory_test_client::on_availability, this,
                                                  std::placeholders::_1, std::placeholders::_2,
                                                  std::placeholders::_3),
                                        MEMORY_MAJOR, MEMORY_MINOR);
    _app->register_message_handler(
            MEMORY_SERVICE, MEMORY_INSTANCE, vsomeip::ANY_EVENT,
            std::bind(&memory_test_client::on_message, this, std::placeholders::_1));
    for (uint16_t i = 0; i < TEST_EVENT_NUMBER; i++) {
        _app->request_event(MEMORY_SERVICE, MEMORY_INSTANCE, MEMORY_EVENT + i,
                            { MEMORY_EVENTGROUP }, vsomeip::event_type_e::ET_FIELD,
                            vsomeip::reliability_type_e::RT_UNRELIABLE);
    }
    _app->request_service(MEMORY_SERVICE, MEMORY_INSTANCE, MEMORY_MAJOR, MEMORY_MINOR);
    for (uint16_t i = 0; i < TEST_EVENT_NUMBER; i++) {
        _app->subscribe(MEMORY_SERVICE, MEMORY_INSTANCE, MEMORY_EVENTGROUP, MEMORY_MAJOR,
                        MEMORY_EVENT + i);
    }
}

void memory_test_client::send_request(std::atomic<bool> &stop_checking_)
{
    std::unique_lock<std::mutex> lk(availability_mutex);
    // Only send the requests when the service availability is secured
    if (condition_availability.wait_for(lk, WAIT_AVAILABILITY,
                                        [=] { return availability; })) {

        // Trigger the test
        auto its_message = vsomeip_utilities::create_standard_vsip_request(
                MEMORY_SERVICE, MEMORY_INSTANCE, MEMORY_START_METHOD, MEMORY_MAJOR,
                vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
        _app->send(its_message);
    }

    EXPECT_TRUE(availability) << "Events expected by the client were not available for 15 seconds ";

    bool stop_watchdog { false };

    // 3. Wait for service to send all the messages
    while (!stop_watchdog) {
        std::this_thread::sleep_for(WATCHDOG_INTERVAL);
        std::lock_guard<std::mutex> lk(event_counter_mutex);
        if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - sec)
                    .count()
            > 10) {
            stop_watchdog = true;
        }
    }
    VSOMEIP_INFO << "received " << received_messages_counter;
    stop_checking_ = true;
}

void memory_test_client::unsubscribe_all()
{
    _app->unsubscribe(MEMORY_SERVICE, MEMORY_INSTANCE, MEMORY_EVENTGROUP);
}

void memory_test_client::stop_service()
{
    auto its_message = vsomeip_utilities::create_standard_vsip_request(
            MEMORY_SERVICE, MEMORY_INSTANCE, MEMORY_STOP_METHOD, MEMORY_MAJOR,
            vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
    _app->send(its_message);
    VSOMEIP_INFO << "sending stop " << received_messages_counter;

}

memory_test_client::~memory_test_client()
{
    stop_service();
    unsubscribe_all();
}

TEST(memory_tests, receive_messages)
{

    // Test steps:
    //      1: Start measuring memory load
    //      2: Send requests for 20 different events
    //      3: Wait for receiving all responses from service
    //      4: Stop measuring load and evaluate load increase
    //
    // At the end evaluate if the threshold of 5% increase in memory load was not surpassed

    std::map<vsomeip::event_t, int> events_to_subscribe;

    for (vsomeip::event_t i = 0; i < TEST_EVENT_NUMBER; i++) {
        events_to_subscribe[MEMORY_EVENT + i] = 0;
    }

    memory_test_client memory_test_client("memory_tests_client", "MTC", events_to_subscribe);

    std::atomic<bool> stop_checking { false };

    // 1. Measure load until stop_checking is triggered
    std::thread memory_checker_thread;
    memory_checker_thread = std::thread([&stop_checking] {
        std::vector<std::uint64_t> test_memory_array;
        std::uint64_t sum { 0 };

        check_memory(test_memory_array, stop_checking);

        for (auto memory_stat : test_memory_array) {
            sum += memory_stat;
            VSOMEIP_INFO << memory_stat;
        }
        double memory_average = static_cast<double>(sum) / static_cast<double>(test_memory_array.size());
            VSOMEIP_INFO << memory_average;

        // 4. Evaluate memory load increase
        for (auto memory_stat : test_memory_array) {
            EXPECT_LT(static_cast<double>(memory_stat),
                    (static_cast<double>(memory_average) * MEMORY_LOAD_LIMIT))
                    << "memory not lesser than "
                    << (static_cast<double>(memory_average) * MEMORY_LOAD_LIMIT);
        }
    });

    // 2. Send a request and wait until all the messages are sent by the service
    memory_test_client.send_request(stop_checking);

    if (memory_checker_thread.joinable()) {
        memory_checker_thread.join();
    }
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
