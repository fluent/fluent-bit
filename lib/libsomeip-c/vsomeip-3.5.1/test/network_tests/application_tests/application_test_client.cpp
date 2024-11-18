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
#include <future>
#include <atomic>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#include "application_test_globals.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class application_test_client : public vsomeip_utilities::base_logger {
public:
    application_test_client(struct application_test::service_info _service_info) :
            vsomeip_utilities::base_logger("APTC", "APPLICATION TEST CLIENT"),
            service_info_(_service_info),
            app_(vsomeip::runtime::get()->create_application("client")),
            wait_until_registered_(true),
            wait_until_service_available_(true),
            wait_for_stop_(true),
            received_responses_(0),
            sent_requests_(0),
            stop_called_(false),
            stop_thread_(std::bind(&application_test_client::wait_for_stop, this)),
            send_thread_(std::bind(&application_test_client::send, this)) {
        if (!app_->init()) {
            ADD_FAILURE() << "[Client] Couldn't initialize application";
            return;
        }
        app_->register_state_handler(
                std::bind(&application_test_client::on_state, this,
                        std::placeholders::_1));

        app_->register_message_handler(vsomeip::ANY_SERVICE,
                vsomeip::ANY_INSTANCE, vsomeip::ANY_METHOD,
                std::bind(&application_test_client::on_message, this,
                        std::placeholders::_1));

        // register availability for all other services and request their event.
        app_->register_availability_handler(service_info_.service_id,
                service_info_.instance_id,
                std::bind(&application_test_client::on_availability, this,
                        std::placeholders::_1, std::placeholders::_2,
                        std::placeholders::_3));
        app_->request_service(service_info_.service_id,
                service_info_.instance_id);
        std::promise<bool> its_promise;
        application_thread_ = std::thread([&](){
            its_promise.set_value(true);
            app_->start();
        });
        EXPECT_TRUE(its_promise.get_future().get());
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    ~application_test_client() {
        send_thread_.join();
        stop_thread_.join();
        application_thread_.join();
    }

    void on_state(vsomeip::state_type_e _state) {
        VSOMEIP_INFO << "[Client] Application " << app_->get_name() << " is "
        << (_state == vsomeip::state_type_e::ST_REGISTERED ?
                "registered." : "deregistered.");

        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            std::scoped_lock its_lock {mutex_};
            wait_until_registered_ = false;
            condition_.notify_one();
        }
    }

    void on_availability(vsomeip::service_t _service, vsomeip::instance_t _instance,
                         bool _is_available) {
        VSOMEIP_INFO << "[Client] Service [" << std::setw(4) << std::setfill('0') << std::hex
                     << _service << "." << _instance << "] is "
                     << (_is_available ? "available" : "not available") << ".";
        std::scoped_lock its_lock {mutex_};
        if (_is_available) {
            wait_until_service_available_ = false;
            condition_.notify_one();
        } else {
            wait_until_service_available_ = true;
            condition_.notify_one();
        }
    }

    void on_message(const std::shared_ptr<vsomeip::message>& _message) {
        ++received_responses_;
        EXPECT_EQ(service_info_.service_id, _message->get_service());
        EXPECT_EQ(service_info_.method_id, _message->get_method());
        EXPECT_EQ(service_info_.instance_id, _message->get_instance());
        VSOMEIP_INFO << "[Client] Received a response with Client/Session [" << std::setfill('0')
                     << std::hex << std::setw(4) << _message->get_client() << "/" << std::setw(4)
                     << _message->get_session() << "]";
    }

    void send() {
        std::unique_lock<std::mutex> its_lock(mutex_);
        while (wait_until_registered_ && !stop_called_) {
            condition_.wait_for(its_lock, std::chrono::milliseconds(100));
        }

        while (wait_until_service_available_  && !stop_called_) {
            condition_.wait_for(its_lock, std::chrono::milliseconds(100));
        }
        its_lock.unlock();
        its_lock.release();

        for (;;) {
            {
                std::scoped_lock its_lock {mutex_};
                if (!wait_until_service_available_ && !stop_called_) {
                    std::shared_ptr<vsomeip::message> its_req =
                            vsomeip::runtime::get()->create_request();
                    its_req->set_service(service_info_.service_id);
                    its_req->set_instance(service_info_.instance_id);
                    its_req->set_method(service_info_.method_id);
                    app_->send(its_req);
                    ++sent_requests_;
                    VSOMEIP_INFO << "[Client] Sent a request to the service!";
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (stop_called_) {
                break;
            }
        }
    }

    void wait_for_stop() {
        std::unique_lock<std::mutex> its_lock(stop_mutex_);
        while (wait_for_stop_) {
            stop_condition_.wait(its_lock);
        }
        VSOMEIP_INFO << "[Client] Going down!";
        app_->clear_all_handler();
        app_->stop();
    }

    void stop(bool check) {
        stop_called_ = true;
        std::scoped_lock its_lock {stop_mutex_};
        wait_for_stop_ = false;
        VSOMEIP_INFO << "[Client] Going down. Sent " << sent_requests_
                << " requests and received " << received_responses_
                << " responses. Delta: " << sent_requests_ - received_responses_;

        if (check) {
            while (sent_requests_ == 0 || sent_requests_ < received_responses_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
            // time to be sure the sent message is sent by routing manager
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            EXPECT_GT(sent_requests_, 0u);
            EXPECT_GT(received_responses_, 0u);
            EXPECT_EQ(sent_requests_, received_responses_);
        }
        stop_condition_.notify_one();
    }

private:
    struct application_test::service_info service_info_;
    std::shared_ptr<vsomeip::application> app_;

    bool wait_until_registered_;
    bool wait_until_service_available_;
    std::mutex mutex_;
    std::condition_variable condition_;

    bool wait_for_stop_;
    std::mutex stop_mutex_;
    std::condition_variable stop_condition_;

    std::atomic<std::uint32_t> received_responses_;
    std::atomic<std::uint32_t> sent_requests_;
    std::atomic<bool> stop_called_;

    std::thread stop_thread_;
    std::thread send_thread_;
    std::thread application_thread_;
};
