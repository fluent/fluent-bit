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

#include "initial_event_test_globals.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class initial_event_test_stop_service : public vsomeip_utilities::base_logger {
public:
    initial_event_test_stop_service(struct initial_event_test::service_info _service_info, bool _is_master) :
            vsomeip_utilities::base_logger("IETS", "INITIAL EVENT TEST STOP SERVICE"),
            service_info_(_service_info),
            is_master_(_is_master),
            app_(vsomeip::runtime::get()->create_application()),
            wait_until_registered_(true),
            wait_until_stop_service_other_node_available_(true),
            wait_until_shutdown_method_called_(true),
            offer_thread_(std::bind(&initial_event_test_stop_service::run, this)),
            wait_for_stop_(true),
            stop_thread_(std::bind(&initial_event_test_stop_service::wait_for_stop, this)),
            called_other_node_(false) {
        if (!app_->init()) {
            offer_thread_.detach();
            stop_thread_.detach();
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }
        app_->register_state_handler(
                std::bind(&initial_event_test_stop_service::on_state, this,
                        std::placeholders::_1));
        app_->register_message_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.method_id,
                std::bind(&initial_event_test_stop_service::on_shutdown_method_called, this,
                        std::placeholders::_1));

        // register availability for all other services and request their event.
        if (is_master_) {
            app_->request_service(
                    initial_event_test::stop_service_slave.service_id,
                    initial_event_test::stop_service_slave.instance_id);
            app_->register_availability_handler(
                    initial_event_test::stop_service_slave.service_id,
                    initial_event_test::stop_service_slave.instance_id,
                    std::bind(&initial_event_test_stop_service::on_availability,
                            this, std::placeholders::_1, std::placeholders::_2,
                            std::placeholders::_3));
        } else {
            app_->request_service(
                    initial_event_test::stop_service_master.service_id,
                    initial_event_test::stop_service_master.instance_id);
            app_->register_availability_handler(
                    initial_event_test::stop_service_master.service_id,
                    initial_event_test::stop_service_master.instance_id,
                    std::bind(&initial_event_test_stop_service::on_availability,
                            this, std::placeholders::_1, std::placeholders::_2,
                            std::placeholders::_3));
        }
        app_->start();
    }

    ~initial_event_test_stop_service() {
        if (offer_thread_.joinable()) {
            offer_thread_.join();
        }
        if (stop_thread_.joinable()) {
            stop_thread_.join();
        }
    }

    void offer() {
        if (is_master_) {
            app_->offer_service(
                    initial_event_test::stop_service_master.service_id,
                    initial_event_test::stop_service_master.instance_id);
        } else {
            app_->offer_service(
                    initial_event_test::stop_service_slave.service_id,
                    initial_event_test::stop_service_slave.instance_id);
        }
    }

    void stop_offer() {
        if (is_master_) {
            app_->stop_offer_service(
                    initial_event_test::stop_service_master.service_id,
                    initial_event_test::stop_service_master.instance_id);
        } else {
            app_->stop_offer_service(
                    initial_event_test::stop_service_slave.service_id,
                    initial_event_test::stop_service_slave.instance_id);
        }
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
        bool notify(false);
        if(_is_available) {
            VSOMEIP_INFO << "[" << std::setw(4) << std::setfill('0') << std::hex
                    << service_info_.service_id << "] Service ["
                    << std::setw(4) << std::setfill('0') << std::hex << _service
                    << "." << _instance << "] is available.";
            if(is_master_) {
                if(_service == initial_event_test::stop_service_slave.service_id
                        && _instance == initial_event_test::stop_service_slave.instance_id) {
                    notify = true;
                }
            } else {
                if(_service == initial_event_test::stop_service_master.service_id
                        && _instance == initial_event_test::stop_service_master.instance_id) {
                    notify = true;
                }
            }
        }
        if (notify) {
            std::lock_guard<std::mutex> its_lock(availability_mutex_);
            wait_until_stop_service_other_node_available_ = false;
            availability_condition_.notify_one();
        }
    }

    void on_shutdown_method_called(const std::shared_ptr<vsomeip::message> &_message) {
        if(_message->get_message_type() == vsomeip::message_type_e::MT_REQUEST_NO_RETURN) {
            VSOMEIP_DEBUG << "Received a request with Client/Session [" << std::setw(4)
            << std::setfill('0') << std::hex << _message->get_client() << "/"
            << std::setw(4) << std::setfill('0') << std::hex
            << _message->get_session() << "] shutdown method called";

            std::lock_guard<std::mutex> its_lock(stop_mutex_);
            wait_for_stop_ = false;
            stop_condition_.notify_one();
        }
    }

    void run() {
        {
            std::unique_lock<std::mutex> its_lock(mutex_);
            while (wait_until_registered_) {
                condition_.wait(its_lock);
            }
        }

        VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                << service_info_.service_id << "] Offering";
        offer();

        {
            std::unique_lock<std::mutex> its_availability_lock(availability_mutex_);
            while (wait_until_stop_service_other_node_available_) {
                availability_condition_.wait(its_availability_lock);
            }
        }

        VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                << service_info_.service_id << "] Calling shutdown method on remote side";

        std::shared_ptr<vsomeip::message> msg(vsomeip::runtime::get()->create_request());
        msg->set_message_type(vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
        if(is_master_) {
            msg->set_service(initial_event_test::stop_service_slave.service_id);
            msg->set_instance(initial_event_test::stop_service_slave.instance_id);
            msg->set_method(initial_event_test::stop_service_slave.method_id);
        } else {
            msg->set_service(initial_event_test::stop_service_master.service_id);
            msg->set_instance(initial_event_test::stop_service_master.instance_id);
            msg->set_method(initial_event_test::stop_service_master.method_id);
        }
        app_->send(msg);
        called_other_node_ = true;
        {
            std::unique_lock<std::mutex> its_lock(mutex_);
            while (wait_until_shutdown_method_called_) {
                auto its_reason = condition_.wait_for(its_lock, std::chrono::milliseconds(250));
                if (its_reason == std::cv_status::timeout) {
                    its_lock.unlock();
                    std::lock_guard<std::mutex> its_guard(stop_mutex_);
                    wait_for_stop_ = false;
                    stop_condition_.notify_one();
                    wait_until_shutdown_method_called_ = false;
                    its_lock.lock();
                }
            }
        }
    }

    void wait_for_stop() {
        static int its_call_number(0);
        its_call_number++;
        {
            std::unique_lock<std::mutex> its_lock(stop_mutex_);
            while (wait_for_stop_) {
                stop_condition_.wait(its_lock);
            }
        }
        VSOMEIP_INFO << "(" << std::dec << its_call_number << ") [" << std::setw(4) << std::setfill('0') << std::hex
                << service_info_.service_id
                << "] shutdown method was called, going down";
        while(!called_other_node_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        // let offer thread exit
        {
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_until_shutdown_method_called_ = false;
            condition_.notify_one();
        }
        app_->clear_all_handler();
        app_->stop();
    }

private:
    initial_event_test::service_info service_info_;
    bool is_master_;
    std::shared_ptr<vsomeip::application> app_;
    std::map<std::pair<vsomeip::service_t, vsomeip::instance_t>, bool> other_services_available_;
    std::map<std::pair<vsomeip::service_t, vsomeip::method_t>, std::uint32_t> other_services_received_notification_;

    bool wait_until_registered_;
    bool wait_until_stop_service_other_node_available_;
    bool wait_until_shutdown_method_called_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::thread offer_thread_;

    std::mutex availability_mutex_;
    std::condition_variable availability_condition_;

    std::atomic<bool> wait_for_stop_;
    std::mutex stop_mutex_;
    std::condition_variable stop_condition_;
    std::thread stop_thread_;

    std::atomic<bool> called_other_node_;
};

static bool is_master = false;

TEST(someip_initial_event_test, wait_for_stop_method_to_be_called)
{
    if(is_master) {
        initial_event_test_stop_service its_sample(initial_event_test::stop_service_master, is_master);
    } else {
        initial_event_test_stop_service its_sample(initial_event_test::stop_service_slave, is_master);
    }
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    if(argc < 2) {
        std::cerr << "Please specify a valid type, like: " << argv[0] << " MASTER" << std::endl;
        std::cerr << "Valid types are in the range of [MASTER,SLAVE]" << std::endl;
        return 1;
    }

    if (argc >= 2 && std::string("MASTER") == std::string(argv[1])) {
        is_master = true;
    } else if (argc >= 2 && std::string("SLAVE") == std::string(argv[1])){
        is_master = false;
    }
    return RUN_ALL_TESTS();
}
#endif
