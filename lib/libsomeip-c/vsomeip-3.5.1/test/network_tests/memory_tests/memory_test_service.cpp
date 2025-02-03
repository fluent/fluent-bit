// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/internal/logger.hpp>
#include <cstring>

#include "memory_test_service.hpp"

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
        VSOMEIP_INFO << "logged service: "<< its_rsssize * its_pagesize;

    }
}
memory_test_service::memory_test_service(const char *app_name_, const char *app_id_)
    : vsomeip_utilities::base_vsip_app(app_name_, app_id_)
{
    for (uint16_t i = 0; i < TEST_EVENT_NUMBER; i++) {
        _app->offer_event(MEMORY_SERVICE, MEMORY_INSTANCE, MEMORY_EVENT + i, { MEMORY_EVENTGROUP },
                          vsomeip::event_type_e::ET_FIELD, std::chrono::milliseconds::zero(), false,
                          true, nullptr, vsomeip::reliability_type_e::RT_UNRELIABLE);
    }
    _app->register_message_handler(
            MEMORY_SERVICE, MEMORY_INSTANCE, MEMORY_START_METHOD,
            std::bind(&memory_test_service::on_start, this, std::placeholders::_1));
    _app->register_message_handler(
            MEMORY_SERVICE, MEMORY_INSTANCE, MEMORY_STOP_METHOD,
            std::bind(&memory_test_service::on_stop, this, std::placeholders::_1));
    _app->offer_service(MEMORY_SERVICE, MEMORY_INSTANCE, MEMORY_MAJOR, MEMORY_MINOR);
}
void memory_test_service::on_start(const std::shared_ptr<vsomeip::message> /*&_message*/)
{
    std::unique_lock<std::mutex> lk(start_mutex);
    received_message = true;
    condition_wait_start.notify_one();
}

void memory_test_service::on_stop(const std::shared_ptr<vsomeip::message> /*&_message*/)
{
    {
        std::unique_lock<std::mutex> lk(stop_mutex);
        condition_wait_stop.notify_one();
    }
    VSOMEIP_INFO << "service: " << __func__ << ": Received a STOP command.";
}

void memory_test_service::message_sender(std::atomic<bool> &stop_checking_)
{
    auto its_payload = vsomeip::runtime::get()->create_payload();
    auto its_payload2 = vsomeip::runtime::get()->create_payload();

    its_payload->set_data(std::vector<uint8_t>(NOTIFY_PAYLOAD_SIZE, 20));
    its_payload2->set_data(std::vector<uint8_t>(NOTIFY_PAYLOAD_SIZE, 10));
    int count { 0 };
    for (int message_no = 0; message_no <= TEST_MESSAGE_NUMBER; message_no++) {
        for (uint16_t i = 0; i < TEST_EVENT_NUMBER; i++) {
            _app->notify(MEMORY_SERVICE, MEMORY_INSTANCE, MEMORY_EVENT + i, its_payload);
            count++;
        }
        std::this_thread::sleep_for(MESSAGE_SENDER_INTERVAL);
        for (uint16_t i = 0; i < TEST_EVENT_NUMBER; i++) {
            _app->notify(MEMORY_SERVICE, MEMORY_INSTANCE, MEMORY_EVENT + i, its_payload2);
            count++;
        }
        std::this_thread::sleep_for(MESSAGE_SENDER_INTERVAL);
    }
    stop_checking_ = true;
    VSOMEIP_INFO << "sent " << count << " messages";
}

// wait for the start message, run the threads to send messages
// and receive the stop message in the end
void memory_test_service::setup_app(const std::function<void(void)> executionHandler_)
{
    std::unique_lock<std::mutex> lk(start_mutex);
    if (condition_wait_start.wait_for(lk, WAIT_START_MESSAGE,
                                      [=] { return received_message; })) {

        // If executionHandler_ is set / not nullptr
        if (executionHandler_) {
            // run send the messages
            executionHandler_();
        }

        {
            // 3. Wait for client to send stop message
            std::unique_lock<std::mutex> lk(stop_mutex);
            condition_wait_stop.wait_for(lk, WAIT_STOP_MESSAGE);
            std::cout << "service: exiting" << std::endl;
        }
    }
}

TEST(memory_test, send_messages)
{

    // Test steps:
    //      1: Start measuring memory load
    //      2: After receiving start message from the client, start sending
    //         notifications (load bigger than 1392 bytes) for each event
    //         TP
    //      3: Wait for client stop message
    //      4: Stop measuring load and evaluate load increase
    //
    // At the end evaluate if the threshold of 5% increase in memory load was not surpassed

    memory_test_service its_service("memory_test_service", "MTS");
    std::atomic<bool> stop_checking { false };

    std::thread memory_checker_thread;

    // 1. Measure load until stop_checking is triggered
    its_service.setup_app([&] {
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
         // 2. Start sending notifications
        its_service.message_sender(stop_checking);
    });

    if (memory_checker_thread.joinable()) {
        memory_checker_thread.join();
    }
}
int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
