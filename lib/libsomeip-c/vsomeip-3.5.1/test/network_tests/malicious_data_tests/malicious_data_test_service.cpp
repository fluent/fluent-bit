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
#include <map>
#include <algorithm>
#include <atomic>
#include <future>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#include "malicious_data_test_globals.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class malicious_data_test_service : public vsomeip_utilities::base_logger {
public:
    malicious_data_test_service(struct malicious_data_test::service_info _service_info, malicious_data_test::test_mode_e _testmode) :
            vsomeip_utilities::base_logger("MDTS", "MALICIOUS DATA TEST SERVICE"),
            service_info_(_service_info),
            testmode_(_testmode),
            app_(vsomeip::runtime::get()->create_application("malicious_data_test_service")),
            wait_until_registered_(true),
            wait_until_shutdown_method_called_(true),
            received_events_(0),
            received_methodcalls_(0),
            offer_thread_(std::bind(&malicious_data_test_service::run, this)) {
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }
        app_->register_state_handler(
                std::bind(&malicious_data_test_service::on_state, this,
                        std::placeholders::_1));

        std::set<vsomeip::eventgroup_t> its_eventgroups;
        its_eventgroups.insert(_service_info.eventgroup_id);
        app_->request_event(service_info_.service_id, service_info_.instance_id,
                    service_info_.event_id, its_eventgroups, vsomeip::event_type_e::ET_EVENT,
                    vsomeip::reliability_type_e::RT_UNKNOWN);
        app_->register_message_handler(vsomeip::ANY_SERVICE,
                vsomeip::ANY_INSTANCE, service_info_.shutdown_method_id,
                std::bind(&malicious_data_test_service::on_shutdown_method_called, this,
                        std::placeholders::_1));
        app_->register_message_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.event_id,
                std::bind(&malicious_data_test_service::on_event, this,
                        std::placeholders::_1));

        app_->register_message_handler(static_cast<vsomeip::service_t>(service_info_.service_id + 1u),
                service_info_.instance_id, 0x1,
                std::bind(&malicious_data_test_service::on_message, this,
                        std::placeholders::_1));

        // request service of client
        app_->request_service(service_info_.service_id, service_info_.instance_id);
        app_->subscribe(service_info_.service_id, service_info_.instance_id,
                service_info_.eventgroup_id, 0,
                service_info_.event_id);

        app_->start();
    }

    ~malicious_data_test_service() {
        if (testmode_ == malicious_data_test::test_mode_e::MALICIOUS_EVENTS) {
            EXPECT_EQ(9u, received_events_);
            EXPECT_EQ(9u, received_methodcalls_);
        }
        offer_thread_.join();
    }

    void offer() {
        app_->offer_service(static_cast<vsomeip::service_t>(service_info_.service_id + 1u), 0x1);
    }

    void stop() {
        app_->stop_offer_service(static_cast<vsomeip::service_t>(service_info_.service_id + 1u), 0x1);
        app_->clear_all_handler();
        app_->stop();
    }

    void on_state(vsomeip::state_type_e _state) {
        VSOMEIP_INFO << "Application " << app_->get_name() << " is "
        << (_state == vsomeip::state_type_e::ST_REGISTERED ?
                "registered." : "deregistered.");

        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_until_registered_ = false;
            condition_.notify_one();
        }
    }

    void on_shutdown_method_called(const std::shared_ptr<vsomeip::message> &_message) {
        app_->send(vsomeip::runtime::get()->create_response(_message));
        VSOMEIP_WARNING << "************************************************************";
        VSOMEIP_WARNING << "Shutdown method called -> going down!";
        VSOMEIP_WARNING << "************************************************************";
        std::lock_guard<std::mutex> its_lock(mutex_);
        wait_until_shutdown_method_called_ = false;
        condition_.notify_one();
    }

    void on_event(const std::shared_ptr<vsomeip::message> &_message) {
        EXPECT_EQ(service_info_.service_id, _message->get_service());
        EXPECT_EQ(service_info_.instance_id, _message->get_instance());
        EXPECT_EQ(service_info_.event_id, _message->get_method());
        EXPECT_EQ(std::uint32_t(0x7F), _message->get_length());
        received_events_++;
    }

    void on_message(const std::shared_ptr<vsomeip::message> &_message) {
        EXPECT_EQ(static_cast<vsomeip::service_t>(service_info_.service_id + 1u), _message->get_service());
        EXPECT_EQ(service_info_.instance_id, _message->get_instance());
        EXPECT_EQ(vsomeip::method_t(0x1), _message->get_method());
        EXPECT_EQ(std::uint32_t(0x7F), _message->get_length());
        received_methodcalls_++;
    }

    void run() {
        VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                << service_info_.service_id << "] Running";
        std::unique_lock<std::mutex> its_lock(mutex_);
        while (wait_until_registered_) {
            condition_.wait(its_lock);
        }

        VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                << service_info_.service_id << "] Offering";
        offer();

        while (wait_until_shutdown_method_called_) {
            condition_.wait(its_lock);
        }
        stop();
    }

private:
    struct malicious_data_test::service_info service_info_;
    malicious_data_test::test_mode_e testmode_;
    std::shared_ptr<vsomeip::application> app_;

    bool wait_until_registered_;
    bool wait_until_shutdown_method_called_;
    std::uint32_t received_events_;
    std::uint32_t received_methodcalls_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::thread offer_thread_;
};

malicious_data_test::test_mode_e its_testmode(malicious_data_test::test_mode_e::MALICIOUS_EVENTS);

TEST(someip_malicious_data_test, block_subscription_handler)
{
    malicious_data_test_service its_sample(malicious_data_test::service, its_testmode);
}


#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    std::string its_passed_testmode = argv[1];
    if (its_passed_testmode == std::string("MALICIOUS_EVENTS")) {
        its_testmode = malicious_data_test::test_mode_e::MALICIOUS_EVENTS;
    } else if (its_passed_testmode == std::string("PROTOCOL_VERSION")) {
        its_testmode = malicious_data_test::test_mode_e::PROTOCOL_VERSION;
    } else if (its_passed_testmode == std::string("MESSAGE_TYPE")) {
        its_testmode = malicious_data_test::test_mode_e::MESSAGE_TYPE;
    } else if (its_passed_testmode == std::string("RETURN_CODE")) {
        its_testmode = malicious_data_test::test_mode_e::RETURN_CODE;
    } else if (its_passed_testmode == std::string("WRONG_HEADER_FIELDS_UDP")) {
        its_testmode = malicious_data_test::test_mode_e::WRONG_HEADER_FIELDS_UDP;
    }
    return RUN_ALL_TESTS();
}
#endif
