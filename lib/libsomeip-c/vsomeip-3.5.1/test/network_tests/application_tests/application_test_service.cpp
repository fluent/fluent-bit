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

class application_test_service : public vsomeip_utilities::base_logger {
public:
    application_test_service(struct application_test::service_info _service_info) :
            vsomeip_utilities::base_logger("APTS", "APPLICATION TEST SERVICE"),
            service_info_(_service_info),
            // service with number 1 uses "routingmanagerd" as application name
            // this way the same json file can be reused for all local tests
            // including the ones with routingmanagerd
            app_(vsomeip::runtime::get()->create_application("service")),
            wait_until_registered_(true),
            stop_called_(false),
            offer_thread_(std::bind(&application_test_service::run, this)) {
        if (!app_->init()) {
            ADD_FAILURE() << "[Service] Couldn't initialize application";
            return;
        }
        app_->register_state_handler(
                std::bind(&application_test_service::on_state, this,
                        std::placeholders::_1));

        app_->register_message_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.method_id,
                std::bind(&application_test_service::on_request, this,
                        std::placeholders::_1));

        app_->register_message_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.shutdown_method_id,
                std::bind(&application_test_service::on_shutdown_method_called, this,
                        std::placeholders::_1));
        std::promise<bool> its_promise;
        application_thread_ = std::thread([&](){
            its_promise.set_value(true);
            app_->start();
        });
        EXPECT_TRUE(its_promise.get_future().get());
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    ~application_test_service() {
        offer_thread_.join();
        application_thread_.join();
    }


    void offer() {
        app_->offer_service(service_info_.service_id, service_info_.instance_id,
                service_info_.major_version, service_info_.minor_version);
    }

    void on_state(vsomeip::state_type_e _state) {
        VSOMEIP_INFO << "[Service] Application " << app_->get_name() << " is "
                     << (_state == vsomeip::state_type_e::ST_REGISTERED ? "registered."
                                                                        : "deregistered.");

        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_until_registered_ = false;
            condition_.notify_one();
        }
    }

    void on_request(const std::shared_ptr<vsomeip::message> &_message) {
        app_->send(vsomeip::runtime::get()->create_response(_message));
        VSOMEIP_INFO << "[Service] Received a request with Client/Session [" << std::setw(4)
                     << std::setfill('0') << std::hex << _message->get_client() << "/"
                     << std::setw(4) << std::setfill('0') << std::hex << _message->get_session()
                     << "]";
    }

    void on_shutdown_method_called(const std::shared_ptr<vsomeip::message> &_message) {
        (void)_message;
        stop();
    }

    void stop() {
        stop_called_ = true;
        app_->stop_offer_service(service_info_.service_id, service_info_.instance_id,
                service_info_.major_version, service_info_.minor_version);
        app_->clear_all_handler();
        app_->stop();
    }

    void run() {
        VSOMEIP_DEBUG << "[Service] [" << std::setw(4) << std::setfill('0') << std::hex
                      << service_info_.service_id << "] is running";
        std::unique_lock<std::mutex> its_lock(mutex_);
        while (wait_until_registered_ && !stop_called_) {
            condition_.wait_for(its_lock, std::chrono::milliseconds(100));
        }

        VSOMEIP_DEBUG << "[Service] [" << std::setw(4) << std::setfill('0') << std::hex
                      << service_info_.service_id << "] is offering";
        offer();
    }

private:
    struct application_test::service_info service_info_;
    std::shared_ptr<vsomeip::application> app_;

    bool wait_until_registered_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::atomic<bool> stop_called_;
    std::thread offer_thread_;
    std::thread application_thread_;
};
