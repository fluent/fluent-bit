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
#endif // ANDROID

#include "offered_services_info_test_globals.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

static std::string service_number;
std::map<vsomeip::service_t, std::set<vsomeip::instance_t>> all_offered_services;
std::map<vsomeip::service_t, std::set<vsomeip::instance_t>> local_offered_services;
std::map<vsomeip::service_t, std::set<vsomeip::instance_t>> remote_offered_services;


class offer_test_service : public vsomeip_utilities::base_logger {
public:
    offer_test_service(struct offer_test::service_info _service_info, struct offer_test::service_info _remote_service_info) :
            vsomeip_utilities::base_logger("OTS1", "OFFER TEST SERVICE"),
            service_info_(_service_info),
            remote_service_info_(_remote_service_info),
            // service with number 1 uses "routingmanagerd" as application name
            // this way the same json file can be reused for all local tests
            // including the ones with routingmanagerd
            app_(vsomeip::runtime::get()->create_application(
                        (service_number == "1") ? "routingmanagerd" :
                                "offered_services_info_test_service" + service_number)),
            wait_until_registered_(true),
            shutdown_method_called_(false),
            offer_thread_(std::bind(&offer_test_service::run, this)) {
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }
        app_->register_state_handler(
                std::bind(&offer_test_service::on_state, this,
                        std::placeholders::_1));

        app_->register_message_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.method_id,
                std::bind(&offer_test_service::on_request, this,
                        std::placeholders::_1));

        app_->register_message_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.shutdown_method_id,
                std::bind(&offer_test_service::on_shutdown_method_called, this,
                        std::placeholders::_1));
        app_->start();
    }

    ~offer_test_service() {
        offer_thread_.join();
    }

    void offer() {
        //offer local services
        app_->offer_service(service_info_.service_id, service_info_.instance_id);
        local_offered_services[service_info_.service_id].insert(service_info_.instance_id);
        all_offered_services[service_info_.service_id].insert(service_info_.instance_id);

        app_->offer_service(service_info_.service_id, (vsomeip::instance_t)(service_info_.instance_id + 1));
        local_offered_services[service_info_.service_id].insert((vsomeip::instance_t)(service_info_.instance_id + 1));
        all_offered_services[service_info_.service_id].insert((vsomeip::instance_t)(service_info_.instance_id + 1));

        // offer remote service ID 0x2222 instance ID 0x2 (port configuration added to json file)
        app_->offer_service(remote_service_info_.service_id, remote_service_info_.instance_id); // reliable and unreliable port
        remote_offered_services[remote_service_info_.service_id].insert(remote_service_info_.instance_id);
        all_offered_services[remote_service_info_.service_id].insert(remote_service_info_.instance_id);


        app_->offer_service((vsomeip::service_t)(remote_service_info_.service_id + 1), (vsomeip::instance_t)(remote_service_info_.instance_id + 1)); // only reliable port
        remote_offered_services[(vsomeip::service_t)(remote_service_info_.service_id + 1)].insert((vsomeip::instance_t)(remote_service_info_.instance_id + 1));
        all_offered_services[(vsomeip::service_t)(remote_service_info_.service_id + 1)].insert((vsomeip::instance_t)(remote_service_info_.instance_id + 1));


        app_->offer_service((vsomeip::service_t)(remote_service_info_.service_id + 2), (vsomeip::instance_t)(remote_service_info_.instance_id + 2)); // only unreliable port
        remote_offered_services[(vsomeip::service_t)(remote_service_info_.service_id + 2)].insert((vsomeip::instance_t)(remote_service_info_.instance_id + 2));
        all_offered_services[(vsomeip::service_t)(remote_service_info_.service_id + 2)].insert((vsomeip::instance_t)(remote_service_info_.instance_id + 2));
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

    void on_request(const std::shared_ptr<vsomeip::message> &_message) {
        app_->send(vsomeip::runtime::get()->create_response(_message));
    }

    void on_shutdown_method_called(const std::shared_ptr<vsomeip::message> &_message) {
        (void)_message;
        shutdown_method_called_ = true;

        app_->stop_offer_service(service_info_.service_id, service_info_.instance_id);
        app_->stop_offer_service(service_info_.service_id, (vsomeip::instance_t)(service_info_.instance_id + 1));

        app_->stop_offer_service(remote_service_info_.service_id, remote_service_info_.instance_id); // reliable and unreliable port
        app_->stop_offer_service((vsomeip::service_t)(remote_service_info_.service_id + 1), (vsomeip::instance_t)(remote_service_info_.instance_id + 1)); // only reliable port
        app_->stop_offer_service((vsomeip::service_t)(remote_service_info_.service_id + 2), (vsomeip::instance_t)(remote_service_info_.instance_id + 2)); // only unreliable port

        app_->clear_all_handler();
        app_->stop();
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
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        VSOMEIP_INFO << "TEST LOCAL SERVICES";
        app_->get_offered_services_async(vsomeip::offer_type_e::OT_LOCAL, std::bind(&offer_test_service::on_offered_services_local, this, std::placeholders::_1));

        if (std::future_status::timeout == all_callbacks_received_.get_future().wait_for(std::chrono::seconds(15))) {
            ADD_FAILURE() << "Didn't receive all callbacks within time";
        }

        while(!shutdown_method_called_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }


    void on_offered_services_local( const std::vector<std::pair<vsomeip::service_t, vsomeip::instance_t>> &_services) {
        std::cout << "ON OFFERED SERVICES LOCAL CALLBACK START" << std::endl;
        EXPECT_EQ(2u, _services.size());
        bool local_service_test_failed(true);
        uint16_t i=0;
        for (auto its_pair : _services) {
            local_service_test_failed = true;
            std::cout << "CALLBACK VALUE -> Service: "<< std::hex << std::get<0>(its_pair) << " instance: " << std::get<1>(its_pair) << std::endl;
            auto found_service = local_offered_services.find(its_pair.first);
            if (found_service != local_offered_services.end()) {
                auto found_instance = found_service->second.find(its_pair.second);
                if (found_instance != found_service->second.end()) {
                    i++;
                    local_service_test_failed = false;
                }
            }
            EXPECT_FALSE(local_service_test_failed);
        }
        EXPECT_EQ(offer_test::num_local_offered_services, i);

        std::cout << "ON OFFERED SERVICES LOCAL CALLBACK END" << std::endl;

        VSOMEIP_INFO << "TEST REMOTE SERVICES";
        app_->get_offered_services_async(vsomeip::offer_type_e::OT_REMOTE, std::bind(&offer_test_service::on_offered_services_remote, this, std::placeholders::_1));
    }


    void on_offered_services_remote( const std::vector<std::pair<vsomeip::service_t, vsomeip::instance_t>> &_services) {
        std::cout << "ON OFFERED SERVICES REMOTE CALLBACK START" << std::endl;
        EXPECT_EQ(3u, _services.size());
        bool remote_service_test_failed(true);
        uint16_t i=0;
        for (auto its_pair : _services) {
            remote_service_test_failed = true;
            std::cout << "CALLBACK VALUE -> Service: " << std::hex  << std::get<0>(its_pair) << " instance: " << std::get<1>(its_pair) << std::endl;
            auto found_service = remote_offered_services.find(its_pair.first);
            if (found_service != remote_offered_services.end()) {
                auto found_instance = found_service->second.find(its_pair.second);
                if (found_instance != found_service->second.end()) {
                    i++;
                    remote_service_test_failed = false;
                }
            }
            EXPECT_FALSE(remote_service_test_failed);
        }
        EXPECT_EQ(offer_test::num_remote_offered_services, i);

        std::cout << "ON OFFERED SERVICES REMOTE CALLBACK END" << std::endl;

        VSOMEIP_INFO << "TEST ALL SERVICES";
        app_->get_offered_services_async(vsomeip::offer_type_e::OT_ALL, std::bind(&offer_test_service::on_offered_services_all, this, std::placeholders::_1));
    }


    void on_offered_services_all( const std::vector<std::pair<vsomeip::service_t, vsomeip::instance_t>> &_services) {
        std::cout << "ON OFFERED SERVICES ALL CALLBACK START" << std::endl;
        EXPECT_EQ(5u, _services.size());
        bool all_service_test_failed(true);
        uint16_t i=0;
        for (auto its_pair : _services) {
            all_service_test_failed = true;
            std::cout << "CALLBACK VALUE -> Service: " << std::hex  << std::get<0>(its_pair) << " instance: " << std::get<1>(its_pair) << std::endl;
            auto found_service = all_offered_services.find(its_pair.first);
            if (found_service != all_offered_services.end()) {
                auto found_instance = found_service->second.find(its_pair.second);
                if (found_instance != found_service->second.end()) {
                    i++;
                    all_service_test_failed = false;
                }
            }
            EXPECT_FALSE(all_service_test_failed);
        }
        EXPECT_EQ(offer_test::num_all_offered_services, i);
        std::cout << "ON OFFERED SERVICES ALL CALLBACK END" << std::endl;
        all_callbacks_received_.set_value();
    }

private:
    struct offer_test::service_info service_info_;
    struct offer_test::service_info remote_service_info_;
    std::shared_ptr<vsomeip::application> app_;

    bool wait_until_registered_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::atomic<bool> shutdown_method_called_;
    std::promise<void> all_callbacks_received_;
    std::thread offer_thread_;
};

TEST(someip_offered_services_info_test, check_offered_services_as_rm_impl)
{
    offer_test_service its_sample(offer_test::service, offer_test::remote_service);
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    if(argc < 2) {
        std::cerr << "Please specify a service number, like: " << argv[0] << " 2" << std::endl;
        return 1;
    }

    service_number = std::string(argv[1]);
    return RUN_ALL_TESTS();
}
#endif
