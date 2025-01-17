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

#ifdef ANDROID
#include "../../implementation/configuration/include/internal_android.hpp"
#else
#include "../../implementation/configuration/include/internal.hpp"
#endif

#include "offered_services_info_test_globals.hpp"
#include "someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

enum operation_mode_e {
    SUBSCRIBE,
    METHODCALL
};

std::map<vsomeip::service_t, std::set<vsomeip::instance_t>> all_offered_services;
std::map<vsomeip::service_t, std::set<vsomeip::instance_t>> local_offered_services;
std::map<vsomeip::service_t, std::set<vsomeip::instance_t>> remote_offered_services;

class offered_services_info_test_client : public vsomeip_utilities::base_logger {
public:
    offered_services_info_test_client(struct offer_test::service_info _service_info,offer_test::service_info _remote_service_info, operation_mode_e _mode) :
            vsomeip_utilities::base_logger("OFIC", "OFFERED SERVICES INFO TEST CLIENT"),
            service_info_(_service_info),
            remote_service_info_(_remote_service_info),
            operation_mode_(_mode),
            app_(vsomeip::runtime::get()->create_application("offered_services_info_test_client")),
            wait_until_registered_(true),
            wait_until_service_available_(true),
            wait_for_stop_(true),
            last_received_response_(std::chrono::steady_clock::now()),
            number_received_responses_(0),
            stop_thread_(std::bind(&offered_services_info_test_client::wait_for_stop, this)),
            test_offered_services_thread_(std::bind(&offered_services_info_test_client::test_offered_services, this)) {
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }

        local_offered_services[service_info_.service_id].insert(service_info_.instance_id);
        all_offered_services[service_info_.service_id].insert(service_info_.instance_id);

        local_offered_services[service_info_.service_id].insert((vsomeip::instance_t)(service_info_.instance_id + 1));
        all_offered_services[service_info_.service_id].insert((vsomeip::instance_t)(service_info_.instance_id + 1));

        // offer remote service ID 0x2222 instance ID 0x2 (port configuration added to json file)
        remote_offered_services[remote_service_info_.service_id].insert(remote_service_info_.instance_id);
        all_offered_services[remote_service_info_.service_id].insert(remote_service_info_.instance_id);

        remote_offered_services[(vsomeip::service_t)(remote_service_info_.service_id + 1)].insert((vsomeip::instance_t)(remote_service_info_.instance_id + 1));
        all_offered_services[(vsomeip::service_t)(remote_service_info_.service_id + 1)].insert((vsomeip::instance_t)(remote_service_info_.instance_id + 1));

        remote_offered_services[(vsomeip::service_t)(remote_service_info_.service_id + 2)].insert((vsomeip::instance_t)(remote_service_info_.instance_id + 2));
        all_offered_services[(vsomeip::service_t)(remote_service_info_.service_id + 2)].insert((vsomeip::instance_t)(remote_service_info_.instance_id + 2));

        app_->register_state_handler(
                std::bind(&offered_services_info_test_client::on_state, this,
                        std::placeholders::_1));

        app_->register_message_handler(vsomeip::ANY_SERVICE,
                vsomeip::ANY_INSTANCE, vsomeip::ANY_METHOD,
                std::bind(&offered_services_info_test_client::on_message, this,
                        std::placeholders::_1));

        app_->register_availability_handler(vsomeip::ANY_SERVICE,
                vsomeip::ANY_INSTANCE,
                std::bind(&offered_services_info_test_client::on_availability, this,
                        std::placeholders::_1, std::placeholders::_2,
                        std::placeholders::_3));
        // request all services
        app_->request_service(service_info_.service_id, service_info_.instance_id);
        app_->request_service(service_info_.service_id, vsomeip::instance_t(service_info_.instance_id + 1));
        app_->request_service(remote_service_info_.service_id, remote_service_info_.instance_id);
        app_->request_service(vsomeip::service_t(remote_service_info_.service_id + 1), vsomeip::instance_t(remote_service_info_.instance_id + 1));
        app_->request_service(vsomeip::service_t(remote_service_info_.service_id + 2), vsomeip::instance_t(remote_service_info_.instance_id + 2));

        app_->start();
    }

    ~offered_services_info_test_client() {
        test_offered_services_thread_.join();
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
        static int services_available =0;
        std::lock_guard<std::mutex> its_lock(mutex_);
        if(_is_available) {
            services_available++;
            if (services_available == 5) {
                wait_until_service_available_ = false;
                condition_.notify_one();
            }
        } else {
            wait_until_service_available_ = true;
            condition_.notify_one();
        }
    }

    void on_message(const std::shared_ptr<vsomeip::message> &_message) {
        if (_message->get_message_type() == vsomeip::message_type_e::MT_RESPONSE) {
            on_response(_message);
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

    void test_offered_services() {
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

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        VSOMEIP_INFO << "TEST LOCAL SERVICES";
        app_->get_offered_services_async(vsomeip::offer_type_e::OT_LOCAL, std::bind(&offered_services_info_test_client::on_offered_services_local, this, std::placeholders::_1));

        // send shutdown command to service
        if (std::future_status::timeout == all_callbacks_received_.get_future().wait_for(std::chrono::seconds(15))) {
            ADD_FAILURE() << "Didn't receive all callbacks within time";
        } else {
            std::shared_ptr<vsomeip::message> its_req = vsomeip::runtime::get()->create_request();
            its_req->set_service(service_info_.service_id);
            its_req->set_instance(service_info_.instance_id);
            its_req->set_method(service_info_.shutdown_method_id);
            app_->send(its_req);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }


        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        {
            std::lock_guard<std::mutex> its_lock(stop_mutex_);
            wait_for_stop_ = false;
            VSOMEIP_INFO << "going down. Sent shutdown command to service";
            stop_condition_.notify_one();
        }
    }

    void on_offered_services_local( const std::vector<std::pair<vsomeip::service_t, vsomeip::instance_t>> &_services) {
        std::cout << "ON OFFERED SERVICES LOCAL CALLBACK START" << std::endl;
        EXPECT_EQ(2u, _services.size());
        bool local_service_test_failed(true);
        for (auto its_pair : _services) {
            local_service_test_failed = true;
            std::cout << "CALLBACK VALUE -> Service: "<< std::hex << std::get<0>(its_pair) << " instance: " << std::get<1>(its_pair) << std::endl;
            auto found_service = local_offered_services.find(its_pair.first);
            if (found_service != local_offered_services.end()) {
                auto found_instance = found_service->second.find(its_pair.second);
                if (found_instance != found_service->second.end()) {
                    local_service_test_failed = false;
                }
            }
            EXPECT_FALSE(local_service_test_failed);
        }
        std::cout << "ON OFFERED SERVICES LOCAL CALLBACK END" << std::endl;
        VSOMEIP_INFO << "TEST REMOTE SERVICES";
        app_->get_offered_services_async(vsomeip::offer_type_e::OT_REMOTE, std::bind(&offered_services_info_test_client::on_offered_services_remote, this, std::placeholders::_1));
    }

    void on_offered_services_remote( const std::vector<std::pair<vsomeip::service_t, vsomeip::instance_t>> &_services) {
        std::cout << "ON OFFERED SERVICES REMOTE CALLBACK START" << std::endl;
        EXPECT_EQ(3u, _services.size());
        bool remote_service_test_failed(true);
        for (auto its_pair : _services) {
            remote_service_test_failed = true;
            std::cout << "CALLBACK VALUE -> Service: " << std::hex  << std::get<0>(its_pair) << " instance: " << std::get<1>(its_pair) << std::endl;
            auto found_service = remote_offered_services.find(its_pair.first);
            if (found_service != remote_offered_services.end()) {
                auto found_instance = found_service->second.find(its_pair.second);
                if (found_instance != found_service->second.end()) {
                    remote_service_test_failed = false;
                }
            }
            EXPECT_FALSE(remote_service_test_failed);
        }
        std::cout << "ON OFFERED SERVICES REMOTE CALLBACK END" << std::endl;
        VSOMEIP_INFO << "TEST ALL SERVICES";
        app_->get_offered_services_async(vsomeip::offer_type_e::OT_ALL, std::bind(&offered_services_info_test_client::on_offered_services_all, this, std::placeholders::_1));
    }

    void on_offered_services_all( const std::vector<std::pair<vsomeip::service_t, vsomeip::instance_t>> &_services) {
        std::cout << "ON OFFERED SERVICES ALL CALLBACK START" << std::endl;
        EXPECT_EQ(5u, _services.size());
        bool all_service_test_failed(true);
        for (auto its_pair : _services) {
            all_service_test_failed = true;
            std::cout << "CALLBACK VALUE -> Service: " << std::hex  << std::get<0>(its_pair) << " instance: " << std::get<1>(its_pair) << std::endl;
            auto found_service = all_offered_services.find(its_pair.first);
            if (found_service != all_offered_services.end()) {
                auto found_instance = found_service->second.find(its_pair.second);
                if (found_instance != found_service->second.end()) {
                    all_service_test_failed = false;
                }
            }
            EXPECT_FALSE(all_service_test_failed);
        }
        std::cout << "ON OFFERED SERVICES ALL CALLBACK END" << std::endl;
        all_callbacks_received_.set_value();
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
    struct offer_test::service_info remote_service_info_;
    operation_mode_e operation_mode_;
    std::shared_ptr<vsomeip::application> app_;

    bool wait_until_registered_;
    bool wait_until_service_available_;
    std::mutex mutex_;
    std::condition_variable condition_;

    bool wait_for_stop_;
    std::mutex stop_mutex_;
    std::condition_variable stop_condition_;

    std::chrono::steady_clock::time_point last_received_response_;
    std::atomic<std::uint32_t> number_received_responses_;
    std::promise<void> all_callbacks_received_;
    std::thread stop_thread_;
    std::thread test_offered_services_thread_;
};

static operation_mode_e passed_mode = operation_mode_e::METHODCALL;

TEST(someip_offered_services_info_test, check_offered_services)
{
    offered_services_info_test_client its_sample(offer_test::service, offer_test::remote_service, passed_mode);
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
