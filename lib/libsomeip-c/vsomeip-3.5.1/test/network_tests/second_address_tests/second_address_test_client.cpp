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

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#include "second_address_test_globals.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class second_address_test_client : public vsomeip_utilities::base_logger {
public:
    second_address_test_client(struct second_address_test::service_info _service_info, bool _use_tcp) :
            vsomeip_utilities::base_logger("SATC", "SECOND ADDRESS TEST CLIENT"),
            service_info_(_service_info),
            use_tcp_(_use_tcp),
            app_(vsomeip::runtime::get()->create_application("second_address_test_client")),
            send_thread_(std::bind(&second_address_test_client::send, this)) {

        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }

        app_->register_state_handler(
                std::bind(&second_address_test_client::on_state, this,
                        std::placeholders::_1));

        app_->register_message_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.request_method_id,
                std::bind(&second_address_test_client::on_message, this,
                        std::placeholders::_1));

        app_->register_message_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.event_id,
                std::bind(&second_address_test_client::on_notification, this,
                        std::placeholders::_1, false));

        app_->register_message_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.selective_event_id,
                std::bind(&second_address_test_client::on_notification, this,
                        std::placeholders::_1, true));

        app_->register_message_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.shutdown_method_id,
                std::bind(&second_address_test_client::on_shutdown_method_called, this,
                        std::placeholders::_1));

        // register availability for all other services and request their event.
        app_->register_availability_handler(service_info_.service_id,
                service_info_.instance_id,
                std::bind(&second_address_test_client::on_availability, this,
                        std::placeholders::_1, std::placeholders::_2,
                        std::placeholders::_3));

        app_->request_service(service_info_.service_id,
                service_info_.instance_id);

        app_->register_subscription_status_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.eventgroup_id,
                service_info_.event_id,
                std::bind(&second_address_test_client::on_subscription_status_changed, this,
                          std::placeholders::_1, std::placeholders::_2,
                          std::placeholders::_3, std::placeholders::_4,
                          std::placeholders::_5, false));

        app_->register_subscription_status_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.selective_eventgroup_id,
                service_info_.selective_event_id,
                std::bind(&second_address_test_client::on_subscription_status_changed, this,
                          std::placeholders::_1, std::placeholders::_2,
                          std::placeholders::_3, std::placeholders::_4,
                          std::placeholders::_5, true));

        app_->start();
    }

    ~second_address_test_client() {
        send_thread_.join();
    }

    void subscribe() {
        std::set<vsomeip::eventgroup_t> its_eventgroups;
        its_eventgroups.insert(service_info_.eventgroup_id);

        app_->request_event(service_info_.service_id,
                service_info_.instance_id, service_info_.event_id,
                its_eventgroups, vsomeip::event_type_e::ET_EVENT);

        its_eventgroups.clear();
        its_eventgroups.insert(service_info_.selective_eventgroup_id);

        app_->request_event(service_info_.service_id,
                service_info_.instance_id, service_info_.selective_event_id,
                its_eventgroups, vsomeip::event_type_e::ET_SELECTIVE_EVENT);

        app_->subscribe(service_info_.service_id, service_info_.instance_id,
                service_info_.eventgroup_id);

        app_->subscribe(service_info_.service_id, service_info_.instance_id,
                service_info_.selective_eventgroup_id);
    }

    void on_state(vsomeip::state_type_e _state) {
        VSOMEIP_DEBUG << "Application " << app_->get_name() << " is "
        << (_state == vsomeip::state_type_e::ST_REGISTERED ?
                "registered" : "deregistered") << " on client.";

        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_until_registered_ = false;
            condition_.notify_one();
        }
    }

    void on_availability(vsomeip::service_t _service, vsomeip::instance_t _instance,
            bool _is_available) {

        VSOMEIP_DEBUG << "Service [" << std::setw(4)
            << std::setfill('0') << std::hex << _service << "." << _instance
            << "] is " << (_is_available ? "available":"not available") << " on client.";

        if (_is_available) {
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_until_service_available_ = false;
            condition_.notify_one();
        }
    }

    void on_message(const std::shared_ptr<vsomeip::message> &_message) {
        EXPECT_EQ(service_info_.service_id, _message->get_service());
        EXPECT_EQ(service_info_.instance_id, _message->get_instance());
        EXPECT_EQ(service_info_.request_method_id, _message->get_method());

        std::lock_guard<std::mutex> its_lock(mutex_);
        auto its_payload = _message->get_payload();
        std::uint32_t data = static_cast<std::uint32_t>(its_payload->get_data()[0]);

        EXPECT_EQ(reply_received_, data);

        wait_until_reply_received_ = false;
        reply_received_++;
        condition_.notify_one();
    }

    void on_notification(const std::shared_ptr<vsomeip::message> &_message,
            bool _selective) {
        EXPECT_EQ(service_info_.service_id, _message->get_service());
        EXPECT_EQ(service_info_.instance_id, _message->get_instance());

        static vsomeip::length_t length_last_received_msg(0);
        EXPECT_GT(_message->get_payload()->get_length(), length_last_received_msg);
        length_last_received_msg = _message->get_payload()->get_length();

        if (_selective) {
            EXPECT_EQ(service_info_.selective_event_id, _message->get_method());

            if (++number_selective_events_received_ == second_address_test::number_of_events_to_send) {
                std::lock_guard<std::mutex> its_lock(mutex_);
                wait_until_selective_events_received_ = false;
                condition_.notify_one();
            }
        } else {
            EXPECT_EQ(service_info_.event_id, _message->get_method());

            if (++number_events_received_ == second_address_test::number_of_events_to_send) {
                std::lock_guard<std::mutex> its_lock(mutex_);
                wait_until_events_received_ = false;
                condition_.notify_one();
            }
        }
    }

    void on_subscription_status_changed(const vsomeip::service_t _service,
                                        const vsomeip::instance_t _instance,
                                        const vsomeip::eventgroup_t _eventgroup,
                                        const vsomeip::event_t _event,
                                        const uint16_t error_code,
                                        bool _selective) {

        VSOMEIP_DEBUG << "Subscription status changed on client";

        EXPECT_EQ(service_info_.service_id, _service);
        EXPECT_EQ(service_info_.instance_id, _instance);
        EXPECT_TRUE((error_code == 0x0u || error_code == 0x7u));

        if (_selective) {
            EXPECT_EQ(service_info_.selective_eventgroup_id, _eventgroup);
            EXPECT_EQ(service_info_.selective_event_id, _event);

            if (error_code == 0x0u) { // accepted
                std::lock_guard<std::mutex> its_lock(mutex_);
                wait_until_selective_subscription_accepted_ = false;
                condition_.notify_one();
            }

        } else {
            EXPECT_EQ(service_info_.eventgroup_id, _eventgroup);
            EXPECT_EQ(service_info_.event_id, _event);

            if (error_code == 0x0u) { // accepted
                std::lock_guard<std::mutex> its_lock(mutex_);
                wait_until_subscription_accepted_ = false;
                condition_.notify_one();
            }
        }
    }

    void on_shutdown_method_called(const std::shared_ptr<vsomeip::message> &_message) {
        EXPECT_EQ(service_info_.service_id, _message->get_service());
        EXPECT_EQ(service_info_.instance_id, _message->get_instance());
        EXPECT_EQ(service_info_.shutdown_method_id, _message->get_method());

        std::lock_guard<std::mutex> its_lock(mutex_);
        wait_until_shutdown_reply_received_ = false;
        condition_.notify_one();
    }

    void send() {
        std::unique_lock<std::mutex> its_lock(mutex_);
        while (wait_until_registered_) {
            condition_.wait(its_lock);
        }

        while (wait_until_service_available_) {
            condition_.wait(its_lock);
        }

        auto its_message = vsomeip::runtime::get()->create_request(use_tcp_);
        its_message->set_service(service_info_.service_id);
        its_message->set_instance(service_info_.instance_id);
        its_message->set_method(service_info_.request_method_id);
        its_message->set_message_type(vsomeip::message_type_e::MT_REQUEST);

        auto its_payload = vsomeip::runtime::get()->create_payload();

        VSOMEIP_DEBUG << "Client sending request messages";

        for (std::uint32_t index = 0; index < second_address_test::number_of_messages_to_send; index++) {
            vsomeip::byte_t *msg_payload = reinterpret_cast<vsomeip::byte_t *>(&index);
            its_payload->set_data(msg_payload, sizeof(index));
            its_message->set_payload(its_payload);
            app_->send(its_message);

            wait_until_reply_received_ = true;
            message_sent_++;

            while (wait_until_reply_received_) {
                condition_.wait(its_lock);
            }
        }

        VSOMEIP_DEBUG << "Client subscribing events";

        subscribe();
        while (wait_until_subscription_accepted_ || wait_until_selective_subscription_accepted_) {
            condition_.wait(its_lock);
        }

        VSOMEIP_DEBUG << "Client requesting event notification";

        its_message->set_method(service_info_.notify_method_id);
        its_message->set_message_type(vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
        its_payload->set_data(&second_address_test::number_of_events_to_send, 1);
        its_message->set_payload(its_payload);
        app_->send(its_message);

        VSOMEIP_DEBUG << "Client waiting event notification";

        while (wait_until_events_received_ || wait_until_selective_events_received_) {
            condition_.wait(its_lock);
        }

        VSOMEIP_DEBUG << "Client shutting down the service";

        // shutdown service
        its_message->set_method(service_info_.shutdown_method_id);
        its_message->set_message_type(vsomeip::message_type_e::MT_REQUEST);
        app_->send(its_message);

        while (wait_until_shutdown_reply_received_) {
            if (std::cv_status::timeout == condition_.wait_for(its_lock, std::chrono::seconds(30))) {
                VSOMEIP_ERROR << "Shutdown request wasn't answered in time!";
                break;
            }
        }

        VSOMEIP_INFO << "Client going down";
        app_->clear_all_handler();
        app_->stop();
    }


private:
    struct second_address_test::service_info service_info_;
    bool use_tcp_;
    std::shared_ptr<vsomeip::application> app_;

    bool wait_until_registered_ = true;
    bool wait_until_service_available_ = true;
    bool wait_until_subscription_accepted_ = true;
    bool wait_until_selective_subscription_accepted_ = true;
    bool wait_until_shutdown_reply_received_ = true;
    bool wait_until_reply_received_ = true;
    bool wait_until_events_received_ = true;
    bool wait_until_selective_events_received_ = true;
    std::mutex mutex_;
    std::condition_variable condition_;

    std::thread send_thread_;
    std::uint32_t message_sent_ = 0;
    std::uint32_t reply_received_ = 0;
    std::uint32_t number_events_received_ = 0;
    std::uint32_t number_selective_events_received_ = 0;
};

static bool use_tcp = false;

TEST(someip_event_test, communicate_using_second_address)
{
    second_address_test_client its_sample(second_address_test::service, use_tcp);
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    if (argc < 2) {
        std::cerr << "Please specify a communication mode, like: " << argv[0] << " TCP" << std::endl;
        std::cerr << "Valid communication modes are UDP or TCP" << std::endl;
        return 1;
    }

    if (std::string("TCP")== std::string(argv[1])) {
        use_tcp = true;
    } else if (std::string("UDP")== std::string(argv[1])) {
        use_tcp = false;
    }

    return RUN_ALL_TESTS();
}
#endif
