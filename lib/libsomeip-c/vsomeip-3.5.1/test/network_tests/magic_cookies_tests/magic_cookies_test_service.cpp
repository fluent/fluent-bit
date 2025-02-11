// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <chrono>
#include <condition_variable>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class magic_cookies_test_service : public vsomeip_utilities::base_logger {
public:
    magic_cookies_test_service(bool _use_static_routing) :
            vsomeip_utilities::base_logger("MGTS", "MAGIC COOKIES TEST SERVICE"),
            app_(vsomeip::runtime::get()->create_application()),
            is_registered_(false),
            use_static_routing_(_use_static_routing),
            blocked_(false),
            offer_thread_(std::bind(&magic_cookies_test_service::run, this)) {
    }

    ~magic_cookies_test_service() {
        offer_thread_.join();
    }
    void init() {
        std::lock_guard<std::mutex> its_lock(mutex_);

        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            exit(EXIT_FAILURE);
        }
        app_->register_message_handler(
                vsomeip_test::TEST_SERVICE_SERVICE_ID,
                vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                vsomeip_test::TEST_SERVICE_METHOD_ID,
                std::bind(&magic_cookies_test_service::on_message, this,
                        std::placeholders::_1));

        app_->register_state_handler(
                std::bind(&magic_cookies_test_service::on_state, this,
                        std::placeholders::_1));

        VSOMEIP_INFO<< "Static routing " << (use_static_routing_ ? "ON" : "OFF");
    }

    void start() {
        app_->start();
    }

    void offer() {
        app_->offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID);
    }

    void stop_offer() {
        app_->stop_offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID);
    }

    void on_state(vsomeip::state_type_e _state) {
        VSOMEIP_INFO << "Application " << app_->get_name() << " is "
        << (_state == vsomeip::state_type_e::ST_REGISTERED ?
                "registered." : "deregistered.");

        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            if (!is_registered_) {
                is_registered_ = true;
                std::lock_guard<std::mutex> its_lock(mutex_);
                blocked_ = true;
                condition_.notify_one();
            }
        } else {
            is_registered_ = false;
        }
    }

    void on_message(const std::shared_ptr<vsomeip::message> &_request) {
        VSOMEIP_INFO << "Received a message with Client/Session [" << std::setw(4)
        << std::setfill('0') << std::hex << _request->get_client() << "/"
        << std::setw(4) << std::setfill('0') << std::hex
        << _request->get_session() << "]";

        std::shared_ptr<vsomeip::message> its_response = vsomeip::runtime::get()
        ->create_response(_request);

        std::shared_ptr<vsomeip::payload> its_payload = vsomeip::runtime::get()
        ->create_payload();
        std::vector<vsomeip::byte_t> its_payload_data;
        for (std::size_t i = 0; i < 120; ++i)
        its_payload_data.push_back(static_cast<vsomeip::byte_t>(i % 256));
        its_payload->set_data(its_payload_data);
        its_response->set_payload(its_payload);

        app_->send(its_response);
        if(_request->get_session() == 0x0F) {
            std::lock_guard<std::mutex> its_lock(mutex_);
            blocked_ = true;
            condition_.notify_one();
        }
    }

    void run() {
        std::unique_lock<std::mutex> its_lock(mutex_);
        while (!blocked_)
            condition_.wait(its_lock);

        bool is_offer(true);
        blocked_ = false;

        if (use_static_routing_) {
            offer();
            while (!blocked_) {
                if(std::cv_status::timeout ==
                        condition_.wait_for(its_lock, std::chrono::seconds(200))) {
                    GTEST_NONFATAL_FAILURE_("Didn't receive all requests within time");
                    break;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            app_->clear_all_handler();
            app_->stop();
        } else {
            while (true) {
                if (is_offer)
                    offer();
                else
                    stop_offer();
                std::this_thread::sleep_for(std::chrono::milliseconds(10000));
                is_offer = !is_offer;
            }
        }
    }

private:
    std::shared_ptr<vsomeip::application> app_;
    bool is_registered_;
    bool use_static_routing_;

    std::mutex mutex_;
    std::condition_variable condition_;
    bool blocked_;
    std::thread offer_thread_;
};

static bool use_static_routing = false;

TEST(someip_magic_cookies_test, reply_to_good_messages)
{
    magic_cookies_test_service its_sample(use_static_routing);
    its_sample.init();
    its_sample.start();
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    std::string static_routing_enable("--static-routing");
    for (int i = 1; i < argc; i++) {
        if (static_routing_enable == argv[i]) {
            use_static_routing = true;
        }
    }
    return RUN_ALL_TESTS();
}
