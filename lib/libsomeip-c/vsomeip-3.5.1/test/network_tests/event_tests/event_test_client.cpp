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

#include "event_test_globals.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class event_test_client : public vsomeip_utilities::base_logger {
public:
    event_test_client(struct event_test::service_info _service_info, event_test::test_mode_e _mode,
                      bool _use_tcp) :
            vsomeip_utilities::base_logger("EVTC", "EVENT TEST CLIENT"),
            service_info_(_service_info),
            test_mode_(_mode),
            use_tcp_(_use_tcp),
            app_(vsomeip::runtime::get()->create_application("event_test_client")),
            service_available_(false),
            wait_until_registered_(true),
            wait_until_service_available_(true),
            wait_until_subscription_accepted_(true),
            wait_until_events_received_(true),
            wait_until_shutdown_reply_received_(true),
            number_events_to_send_(50),
            number_events_received_(0),
            send_thread_(std::bind(&event_test_client::send, this)) {
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }
        app_->register_state_handler(
                std::bind(&event_test_client::on_state, this,
                        std::placeholders::_1));

        app_->register_message_handler(vsomeip::ANY_SERVICE,
                vsomeip::ANY_INSTANCE, vsomeip::ANY_METHOD,
                std::bind(&event_test_client::on_message, this,
                        std::placeholders::_1));

        // register availability for all other services and request their event.
        app_->register_availability_handler(service_info_.service_id,
                service_info_.instance_id,
                std::bind(&event_test_client::on_availability, this,
                        std::placeholders::_1, std::placeholders::_2,
                        std::placeholders::_3));
        app_->request_service(service_info_.service_id,
                service_info_.instance_id);

        std::set<vsomeip::eventgroup_t> its_eventgroups;
        its_eventgroups.insert(service_info_.eventgroup_id);
        app_->request_event(service_info_.service_id,
                service_info_.instance_id, service_info_.event_id,
                its_eventgroups, vsomeip::event_type_e::ET_EVENT,
                (use_tcp_ ? vsomeip::reliability_type_e::RT_RELIABLE : vsomeip::reliability_type_e::RT_UNRELIABLE));
        app_->register_subscription_status_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.eventgroup_id,
                service_info_.event_id,
                std::bind(&event_test_client::on_subscription_status_changed, this,
                          std::placeholders::_1, std::placeholders::_2,
                          std::placeholders::_3, std::placeholders::_4,
                          std::placeholders::_5));
        app_->subscribe(service_info_.service_id, service_info_.instance_id,
                service_info_.eventgroup_id);

        app_->start();
    }

    ~event_test_client() {
        send_thread_.join();
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

    void on_availability(vsomeip::service_t _service,
                         vsomeip::instance_t _instance, bool _is_available) {
            VSOMEIP_INFO << "Service [" << std::setw(4)
            << std::setfill('0') << std::hex << _service << "." << _instance
            << "] is " << (_is_available ? "available":"not available") << ".";
            if (_is_available) {
                std::lock_guard<std::mutex> its_lock(mutex_);
                wait_until_service_available_ = false;
                condition_.notify_one();
            }
    }

    void on_message(const std::shared_ptr<vsomeip::message> &_message) {
        if(_message->get_message_type() == vsomeip::message_type_e::MT_NOTIFICATION) {
            on_notification(_message);
        } else if (_message->get_message_type() == vsomeip::message_type_e::MT_RESPONSE) {
            on_response(_message);
        }
    }

    void on_notification(const std::shared_ptr<vsomeip::message> &_message) {
        EXPECT_EQ(service_info_.service_id, _message->get_service());
        EXPECT_EQ(service_info_.instance_id, _message->get_instance());
        EXPECT_EQ(service_info_.event_id, _message->get_method());
        if (test_mode_ == event_test::test_mode_e::PAYLOAD_FIXED) {
            EXPECT_EQ(event_test::payload_fixed_length, _message->get_payload()->get_length());
        } else if (test_mode_ == event_test::test_mode_e::PAYLOAD_DYNAMIC) {
            static vsomeip::length_t length_last_received_msg(0);
            EXPECT_GT(_message->get_payload()->get_length(), length_last_received_msg);
            length_last_received_msg = _message->get_payload()->get_length();

        }
        if (++number_events_received_ == number_events_to_send_) {
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_until_events_received_ = false;
            condition_.notify_one();
        }

        VSOMEIP_DEBUG
        << "Received a notification with Client/Session [" << std::setw(4)
        << std::setfill('0') << std::hex << _message->get_client() << "/"
        << std::setw(4) << std::setfill('0') << std::hex
        << _message->get_session() << "] from Service/Method ["
        << std::setw(4) << std::setfill('0') << std::hex
        << _message->get_service() << "/" << std::setw(4) << std::setfill('0')
        << std::hex << _message->get_method() << "]";

    }

    void on_response(const std::shared_ptr<vsomeip::message> &_message) {
        EXPECT_EQ(service_info_.service_id, _message->get_service());
        EXPECT_EQ(service_info_.shutdown_method_id, _message->get_method());
        EXPECT_EQ(service_info_.instance_id, _message->get_instance());
        std::lock_guard<std::mutex> its_lock(mutex_);
        wait_until_shutdown_reply_received_ = false;
        condition_.notify_one();
    }

    void on_subscription_status_changed(const vsomeip::service_t _service,
                                        const vsomeip::instance_t _instance,
                                        const vsomeip::eventgroup_t _eventgroup,
                                        const vsomeip::event_t _event,
                                        const uint16_t error_code) {
        EXPECT_EQ(service_info_.service_id, _service);
        EXPECT_EQ(service_info_.instance_id, _instance);
        EXPECT_EQ(service_info_.eventgroup_id, _eventgroup);
        EXPECT_EQ(service_info_.event_id, _event);
        EXPECT_TRUE((error_code == 0x0u || error_code == 0x7u));
        if (error_code == 0x0u) { // accepted
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_until_subscription_accepted_ = false;
            condition_.notify_one();
        }
    }

    void send() {
        {
            std::unique_lock<std::mutex> its_lock(mutex_);
            while (wait_until_registered_) {
                condition_.wait(its_lock);
            }

            while (wait_until_service_available_) {
                condition_.wait(its_lock);
            }

            while (wait_until_subscription_accepted_) {
                if (std::cv_status::timeout == condition_.wait_for(its_lock, std::chrono::seconds(30))) {
                    VSOMEIP_ERROR << "Subscription wasn't accepted in time!";
                    break;
                }
            }

            // call notify method
            auto its_message = vsomeip::runtime::get()->create_request(use_tcp_);
            its_message->set_service(service_info_.service_id);
            its_message->set_instance(service_info_.instance_id);
            its_message->set_method(service_info_.notify_method_id);
            its_message->set_message_type(vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
            auto its_payload = vsomeip::runtime::get()->create_payload();
            its_payload->set_data(std::vector<vsomeip::byte_t>({
                    static_cast<vsomeip::byte_t>(test_mode_),
                    static_cast<vsomeip::byte_t>(number_events_to_send_)}));
            its_message->set_payload(its_payload);
            app_->send(its_message);

            while (wait_until_events_received_) {
                if (std::cv_status::timeout == condition_.wait_for(its_lock, std::chrono::seconds(30))) {
                    VSOMEIP_ERROR << "Didn't receive events in time!";
                    break;
                }
            }

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
        }
        VSOMEIP_INFO << "going down";
        app_->clear_all_handler();
        app_->stop();
    }


private:
    struct event_test::service_info service_info_;
    event_test::test_mode_e test_mode_;
    bool use_tcp_;
    std::shared_ptr<vsomeip::application> app_;
    bool service_available_;

    bool wait_until_registered_;
    bool wait_until_service_available_;
    bool wait_until_subscription_accepted_;
    bool wait_until_events_received_;
    bool wait_until_shutdown_reply_received_;
    std::mutex mutex_;
    std::condition_variable condition_;

    const std::uint8_t number_events_to_send_;
    std::atomic<std::uint32_t> number_events_received_;
    std::thread send_thread_;
};

static event_test::test_mode_e passed_mode = event_test::test_mode_e::PAYLOAD_FIXED;
static bool use_tcp = false;

TEST(someip_event_test, subscribe_or_call_method_at_service)
{
    event_test_client its_sample(event_test::service, passed_mode, use_tcp);
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    if (argc < 3) {
        std::cerr << "Please specify a operation mode, like: " << argv[0] << "PAYLOAD_FIXED TCP" << std::endl;
        std::cerr << "Valid operation modes are PAYLOAD_FIXED and PAYLOAD_DYNAMIC" << std::endl;
        std::cerr << "Valid communication modes are UDP or TCP" << std::endl;
        return 1;
    }

    if (std::string("PAYLOAD_FIXED") == std::string(argv[1])) {
        passed_mode = event_test::test_mode_e::PAYLOAD_FIXED;
    } else if (std::string("PAYLOAD_DYNAMIC") == std::string(argv[1])) {
        passed_mode = event_test::test_mode_e::PAYLOAD_DYNAMIC;
    } else {
        std::cerr << "Wrong operation mode passed, exiting" << std::endl;
        std::cerr << "Please specify a operation mode, like: " << argv[0] << " PAYLOAD_FIXED" << std::endl;
        std::cerr << "Valid operation modes are PAYLOAD_FIXED and PAYLOAD_DYNAMIC" << std::endl;
        return 1;
    }
    if (std::string("TCP")== std::string(argv[2])) {
        use_tcp = true;
    } else if (std::string("UDP")== std::string(argv[2])) {
        use_tcp = false;
    }
    return RUN_ALL_TESTS();
}
#endif
