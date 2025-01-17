// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <chrono>
#include <condition_variable>
#include <iomanip>
#include <memory>
#include <thread>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>
#include "../implementation/runtime/include/application_impl.hpp"
#include "../implementation/routing/include/routing_manager.hpp"

class magic_cookies_test_client : public vsomeip_utilities::base_logger {
public:
    magic_cookies_test_client()
        : vsomeip_utilities::base_logger("MCTC", "MAGIC COOKIES TEST CLIENT"),
          app_(new vsomeip::application_impl("", "")),
          is_blocked_(false),
          sent_messages_good_(8),
          sent_messages_bad_(7),
          received_responses_(0),
          received_errors_(0),
          wait_for_replies_(true),
          runner_(std::bind(&magic_cookies_test_client::run, this)) {
    }

    void init() {
        VSOMEIP_INFO << "Initializing...";
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            exit(EXIT_FAILURE);
        }

        app_->register_state_handler(
                std::bind(
                    &magic_cookies_test_client::on_state,
                    this,
                    std::placeholders::_1));

        app_->register_message_handler(
                vsomeip::ANY_SERVICE, vsomeip_test::TEST_SERVICE_INSTANCE_ID, vsomeip::ANY_METHOD,
                std::bind(&magic_cookies_test_client::on_message,
                          this,
                          std::placeholders::_1));

        app_->register_availability_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                std::bind(&magic_cookies_test_client::on_availability,
                          this,
                          std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
                          vsomeip::DEFAULT_MAJOR, vsomeip::DEFAULT_MINOR);
    }

    void start() {
        VSOMEIP_INFO << "Starting...";
        app_->start();
    }

    void stop() {
        VSOMEIP_INFO << "Stopping...";
        app_->clear_all_handler();
        app_->stop();
    }

    void on_state(vsomeip::state_type_e _state) {
        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            VSOMEIP_INFO << "Client registration done.";
            app_->request_service(vsomeip_test::TEST_SERVICE_SERVICE_ID,
                                  vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                                  vsomeip::ANY_MAJOR, vsomeip::ANY_MINOR);
        }
    }

    void on_availability(vsomeip::service_t _service, vsomeip::instance_t _instance, bool _is_available) {
        VSOMEIP_INFO << "Service ["
                << std::setw(4) << std::setfill('0') << std::hex << _service << "." << _instance
                << "] is "
                << (_is_available ? "available." : "NOT available.");

        if (vsomeip_test::TEST_SERVICE_SERVICE_ID == _service && vsomeip_test::TEST_SERVICE_INSTANCE_ID == _instance) {
            static bool is_available = false;
            if (is_available  && !_is_available) is_available = false;
            else if (_is_available && !is_available) {
                is_available = true;
                std::lock_guard< std::mutex > its_lock(mutex_);
                is_blocked_ = true;
                condition_.notify_one();
            }
        }
    }

    void on_message(const std::shared_ptr< vsomeip::message > &_response) {
        if (_response->get_return_code() == vsomeip::return_code_e::E_OK) {
            VSOMEIP_INFO << "Received a response from Service ["
                    << std::setw(4) << std::setfill('0') << std::hex << _response->get_service()
                    << "."
                    << std::setw(4) << std::setfill('0') << std::hex << _response->get_instance()
                    << "] to Client/Session ["
                    << std::setw(4) << std::setfill('0') << std::hex << _response->get_client()
                    << "/"
                    << std::setw(4) << std::setfill('0') << std::hex << _response->get_session()
                    << "]";
            received_responses_++;
        } else if (_response->get_return_code() == vsomeip::return_code_e::E_MALFORMED_MESSAGE) {
            VSOMEIP_INFO << "Received an error message from Service ["
                    << std::setw(4) << std::setfill('0') << std::hex << _response->get_service()
                    << "."
                    << std::setw(4) << std::setfill('0') << std::hex << _response->get_instance()
                    << "] to Client/Session ["
                    << std::setw(4) << std::setfill('0') << std::hex << _response->get_client()
                    << "/"
                    << std::setw(4) << std::setfill('0') << std::hex << _response->get_session()
                    << "]";
            received_errors_++;
        }
        if (received_errors_ == sent_messages_bad_
                && received_responses_ == sent_messages_good_) {
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_for_replies_ = false;
            condition_.notify_one();
        }
    }

    void join() {
        runner_.join();
    }

    void run() {
        std::unique_lock< std::mutex > its_lock(mutex_);
        while (!is_blocked_) {
            if (std::cv_status::timeout ==
                    condition_.wait_for(its_lock, std::chrono::milliseconds(5000))) {
                GTEST_NONFATAL_FAILURE_("Service didn't become available within 5s.");
                break;
            }
        }
        VSOMEIP_INFO << "Running...";

        vsomeip::routing_manager *its_routing = app_->get_routing_manager();

        vsomeip::byte_t its_good_payload_data[] = {
                0x12, 0x34, 0x84, 0x21,
                0x00, 0x00, 0x00, 0x11,
                0x13, 0x43, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00,
                0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
        };

        vsomeip::byte_t its_bad_payload_data[] = {
                0x12, 0x34, 0x84, 0x21,
                0x00, 0x00, 0x01, 0x23,
                0x13, 0x43, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00,
                0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
        };

        // Test sequence
        its_good_payload_data[11] = 0x01;
        its_routing->send(0x1343, its_good_payload_data, sizeof(its_good_payload_data), vsomeip_test::TEST_SERVICE_INSTANCE_ID, true);
        std::this_thread::sleep_for(std::chrono::seconds(11));
        its_bad_payload_data[11] = 0x02;
        its_routing->send(0x1343, its_bad_payload_data, sizeof(its_bad_payload_data), vsomeip_test::TEST_SERVICE_INSTANCE_ID, true);
        std::this_thread::sleep_for(std::chrono::seconds(11));
        its_good_payload_data[11] = 0x03;
        its_routing->send(0x1343, its_good_payload_data, sizeof(its_good_payload_data), vsomeip_test::TEST_SERVICE_INSTANCE_ID, true);
        std::this_thread::sleep_for(std::chrono::seconds(11));
        its_bad_payload_data[11] = 0x04;
        its_routing->send(0x1343, its_bad_payload_data, sizeof(its_bad_payload_data), vsomeip_test::TEST_SERVICE_INSTANCE_ID, true);
        std::this_thread::sleep_for(std::chrono::seconds(11));
        its_bad_payload_data[11] = 0x05;
        its_routing->send(0x1343, its_bad_payload_data, sizeof(its_bad_payload_data), vsomeip_test::TEST_SERVICE_INSTANCE_ID, true);
        std::this_thread::sleep_for(std::chrono::seconds(11));
        its_good_payload_data[11] = 0x06;
        its_routing->send(0x1343, its_good_payload_data, sizeof(its_good_payload_data), vsomeip_test::TEST_SERVICE_INSTANCE_ID, true);
        std::this_thread::sleep_for(std::chrono::seconds(11));
        its_good_payload_data[11] = 0x07;
        its_routing->send(0x1343, its_good_payload_data, sizeof(its_good_payload_data), vsomeip_test::TEST_SERVICE_INSTANCE_ID, true);
        std::this_thread::sleep_for(std::chrono::seconds(11));
        its_bad_payload_data[11] = 0x08;
        its_routing->send(0x1343, its_bad_payload_data, sizeof(its_bad_payload_data), vsomeip_test::TEST_SERVICE_INSTANCE_ID, true);
        std::this_thread::sleep_for(std::chrono::seconds(11));
        its_bad_payload_data[11] = 0x09;
        its_routing->send(0x1343, its_bad_payload_data, sizeof(its_bad_payload_data), vsomeip_test::TEST_SERVICE_INSTANCE_ID, true);
        std::this_thread::sleep_for(std::chrono::seconds(11));
        its_bad_payload_data[11] = 0x0A;
        its_routing->send(0x1343, its_bad_payload_data, sizeof(its_bad_payload_data), vsomeip_test::TEST_SERVICE_INSTANCE_ID, true);
        std::this_thread::sleep_for(std::chrono::seconds(11));
        its_good_payload_data[11] = 0x0B;
        its_routing->send(0x1343, its_good_payload_data, sizeof(its_good_payload_data), vsomeip_test::TEST_SERVICE_INSTANCE_ID, true);
        std::this_thread::sleep_for(std::chrono::seconds(11));
        its_good_payload_data[11] = 0x0C;
        its_routing->send(0x1343, its_good_payload_data, sizeof(its_good_payload_data), vsomeip_test::TEST_SERVICE_INSTANCE_ID, true);
        std::this_thread::sleep_for(std::chrono::seconds(11));
        its_good_payload_data[11] = 0x0D;
        its_routing->send(0x1343, its_good_payload_data, sizeof(its_good_payload_data), vsomeip_test::TEST_SERVICE_INSTANCE_ID, true);
        std::this_thread::sleep_for(std::chrono::seconds(11));
        its_bad_payload_data[11] = 0x0E;
        its_routing->send(0x1343, its_bad_payload_data, sizeof(its_bad_payload_data), vsomeip_test::TEST_SERVICE_INSTANCE_ID, true);
        std::this_thread::sleep_for(std::chrono::seconds(11));
        its_good_payload_data[11] = 0x0F;
        its_routing->send(0x1343, its_good_payload_data, sizeof(its_good_payload_data), vsomeip_test::TEST_SERVICE_INSTANCE_ID, true);

        while (wait_for_replies_) {
            if(std::cv_status::timeout ==
                    condition_.wait_for(its_lock, std::chrono::milliseconds(5000))) {
                GTEST_NONFATAL_FAILURE_("Didn't receive all replies/errors in time");
                break;
            }
        }
        EXPECT_EQ(sent_messages_good_, received_responses_);
        EXPECT_EQ(sent_messages_bad_, received_errors_);
        stop();
    }

private:
    std::shared_ptr< vsomeip::application_impl > app_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool is_blocked_;
    const std::uint32_t sent_messages_good_;
    const std::uint32_t sent_messages_bad_;
    std::atomic<std::uint32_t> received_responses_;
    std::atomic<std::uint32_t> received_errors_;
    bool wait_for_replies_;
    std::thread runner_;
};

TEST(someip_magic_cookies_test, send_good_and_bad_messages)
{
    magic_cookies_test_client its_client;
    its_client.init();
    its_client.start();
    its_client.join();
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}


