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

#ifdef ANDROID
#include "../../implementation/configuration/include/internal_android.hpp"
#else
#include "../../implementation/configuration/include/internal.hpp"
#endif // ANDROID

#include "offer_test_globals.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

enum operation_mode_e {
    SUBSCRIBE,
    METHODCALL
};

class offer_test_client : public vsomeip_utilities::base_logger {
public:
    offer_test_client(struct offer_test::service_info _service_info, operation_mode_e _mode) :
            vsomeip_utilities::base_logger("OTC1", "OFFER TEST CLIENT"),
            service_info_(_service_info),
            operation_mode_(_mode),
            app_(vsomeip::runtime::get()->create_application("offer_test_client")),
            wait_until_registered_(true),
            wait_until_service_available_(true),
            wait_for_stop_(true),
            last_received_counter_(0),
            last_received_response_(std::chrono::steady_clock::now()),
            number_received_responses_(0),
            stop_thread_(std::bind(&offer_test_client::wait_for_stop, this)),
            send_thread_(std::bind(&offer_test_client::send, this)) {
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }
        app_->register_state_handler(
                std::bind(&offer_test_client::on_state, this,
                        std::placeholders::_1));

        app_->register_message_handler(vsomeip::ANY_SERVICE,
                vsomeip::ANY_INSTANCE, vsomeip::ANY_METHOD,
                std::bind(&offer_test_client::on_message, this,
                        std::placeholders::_1));

        // register availability for all other services and request their event.
        app_->register_availability_handler(service_info_.service_id,
                service_info_.instance_id,
                std::bind(&offer_test_client::on_availability, this,
                        std::placeholders::_1, std::placeholders::_2,
                        std::placeholders::_3));
        app_->request_service(service_info_.service_id,
                service_info_.instance_id);

        if (operation_mode_ == operation_mode_e::SUBSCRIBE) {
            std::set<vsomeip::eventgroup_t> its_eventgroups;
            its_eventgroups.insert(service_info_.eventgroup_id);
            app_->request_event(service_info_.service_id,
                    service_info_.instance_id, service_info_.event_id,
                    its_eventgroups, vsomeip::event_type_e::ET_EVENT,
                    vsomeip::reliability_type_e::RT_BOTH);

            app_->subscribe(service_info_.service_id, service_info_.instance_id,
                    service_info_.eventgroup_id, vsomeip::DEFAULT_MAJOR);
        }

        app_->start();
    }

    ~offer_test_client() {
        send_thread_.join();
        stop_thread_.join();
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
            std::lock_guard<std::mutex> its_lock(mutex_);
            if(_is_available) {
                wait_until_service_available_ = false;
                condition_.notify_one();
            } else {
                wait_until_service_available_ = true;
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
        std::shared_ptr<vsomeip::payload> its_payload(_message->get_payload());
        EXPECT_EQ(4u, its_payload->get_length());
        vsomeip::byte_t *d = its_payload->get_data();
        static std::uint32_t number_received_notifications(0);
        std::uint32_t counter(0);
        counter |= static_cast<std::uint32_t>(d[0] << 24);
        counter |= static_cast<std::uint32_t>(d[0] << 16);
        counter = counter | static_cast<std::uint32_t>((d[2] << 8));
        counter = counter | static_cast<std::uint32_t>(d[3]);

        VSOMEIP_DEBUG
        << "Received a notification with Client/Session [" << std::setw(4)
        << std::setfill('0') << std::hex << _message->get_client() << "/"
        << std::setw(4) << std::setfill('0') << std::hex
        << _message->get_session() << "] from Service/Method ["
        << std::setw(4) << std::setfill('0') << std::hex
        << _message->get_service() << "/" << std::setw(4) << std::setfill('0')
        << std::hex << _message->get_method() << "] got:" << std::dec << counter;

        ASSERT_GT(counter, last_received_counter_);
        last_received_counter_ = counter;
        ++number_received_notifications;

        if(number_received_notifications >= 250) {
            std::lock_guard<std::mutex> its_lock(stop_mutex_);
            wait_for_stop_ = false;
            VSOMEIP_INFO << "going down";
            stop_condition_.notify_one();
        }
    }

    void on_response(const std::shared_ptr<vsomeip::message> &_message) {
        ++number_received_responses_;
        static bool first(true);
        if (first) {
            first = false;
            last_received_response_  = std::chrono::steady_clock::now();
            return;
        }
        EXPECT_EQ(service_info_.service_id, _message->get_service());
        EXPECT_EQ(service_info_.method_id, _message->get_method());
        EXPECT_EQ(service_info_.instance_id, _message->get_instance());
        ASSERT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - last_received_response_).count(),
                  (std::chrono::milliseconds(VSOMEIP_DEFAULT_WATCHDOG_TIMEOUT)
                                  + std::chrono::milliseconds(1000)).count());
        last_received_response_ = std::chrono::steady_clock::now();
        std::cout << ".";
        std::cout.flush();
    }

    void send() {
        if (operation_mode_ != operation_mode_e::METHODCALL) {
            return;
        }
        std::unique_lock<std::mutex> its_lock(mutex_);
        while (wait_until_registered_) {
            condition_.wait(its_lock);
        }

        while (wait_until_service_available_) {
            condition_.wait(its_lock);
        }
        its_lock.unlock();
        its_lock.release();

        for (int var = 0; var < offer_test::number_of_messages_to_send; ++var) {
            bool send(false);
            {
                std::lock_guard<std::mutex> its_lock(mutex_);
                send = !wait_until_service_available_;
            }
            if (send) {
                std::shared_ptr<vsomeip::message> its_req = vsomeip::runtime::get()->create_request();
                its_req->set_service(service_info_.service_id);
                its_req->set_instance(service_info_.instance_id);
                its_req->set_method(service_info_.method_id);
                app_->send(its_req);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        {
            std::lock_guard<std::mutex> its_lock(stop_mutex_);
            wait_for_stop_ = false;
            VSOMEIP_INFO << "going down. Sent " << offer_test::number_of_messages_to_send
                    << " requests and received " << number_received_responses_
                    << " responses";
            stop_condition_.notify_one();
        }
    }

    void wait_for_stop() {
        std::unique_lock<std::mutex> its_lock(stop_mutex_);
        while (wait_for_stop_) {
            stop_condition_.wait(its_lock);
        }
        VSOMEIP_INFO << "going down";
        app_->clear_all_handler();
        app_->stop();
    }

private:
    struct offer_test::service_info service_info_;
    operation_mode_e operation_mode_;
    std::shared_ptr<vsomeip::application> app_;

    bool wait_until_registered_;
    bool wait_until_service_available_;
    std::mutex mutex_;
    std::condition_variable condition_;

    bool wait_for_stop_;
    std::mutex stop_mutex_;
    std::condition_variable stop_condition_;

    std::uint32_t last_received_counter_;
    std::chrono::steady_clock::time_point last_received_response_;
    std::atomic<std::uint32_t> number_received_responses_;
    std::thread stop_thread_;
    std::thread send_thread_;
};

static operation_mode_e passed_mode = operation_mode_e::SUBSCRIBE;

TEST(someip_offer_test, subscribe_or_call_method_at_service)
{
    offer_test_client its_sample(offer_test::service, passed_mode);
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    if(argc < 2) {
        std::cerr << "Please specify a operation mode, like: " << argv[0] << " SUBSCRIBE" << std::endl;
        std::cerr << "Valid operation modes are SUBSCRIBE and METHODCALL" << std::endl;
        return 1;
    }

    if (std::string("SUBSCRIBE") == std::string(argv[1])) {
        passed_mode = operation_mode_e::SUBSCRIBE;
    } else if (std::string("METHODCALL") == std::string(argv[1])) {
        passed_mode = operation_mode_e::METHODCALL;
    } else {
        std::cerr << "Wrong operation mode passed, exiting" << std::endl;
        std::cerr << "Please specify a operation mode, like: " << argv[0] << " SUBSCRIBE" << std::endl;
        std::cerr << "Valid operation modes are SUBSCRIBE and METHODCALL" << std::endl;
        return 1;
    }

#if 0
    if (argc >= 4 && std::string("SAME_SERVICE_ID") == std::string(argv[3])) {
        use_same_service_id = true;
    } else {
        use_same_service_id = false;
    }
#endif
    return RUN_ALL_TESTS();
}
#endif
