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

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../someip_test_globals.hpp"
#include "offer_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

static std::string service_number;

class offer_test_service : public vsomeip_utilities::base_logger {
public:
    offer_test_service(struct offer_test::service_info _service_info) :
            vsomeip_utilities::base_logger("OTSE", "OFFER TEST SERVICE EXTERNAL"),
            service_info_(_service_info),
            // service with number 1 uses "routingmanagerd" as application name
            // this way the same json file can be reused for all local tests
            // including the ones with routingmanagerd
            app_(vsomeip::runtime::get()->create_application(
                        (service_number == "1") ? "routingmanagerd" :
                                "offer_test_service" + service_number)),
            wait_until_registered_(true),
            wait_until_service_available_(true),
            offer_thread_(std::bind(&offer_test_service::run, this)) {
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }
        app_->register_state_handler(
                std::bind(&offer_test_service::on_state, this,
                        std::placeholders::_1));

        app_->register_availability_handler(service_info_.service_id,
                service_info_.instance_id,
                std::bind(&offer_test_service::on_availability, this,
                        std::placeholders::_1, std::placeholders::_2,
                        std::placeholders::_3));
        app_->request_service(service_info_.service_id,
                service_info_.instance_id);
        app_->start();
    }

    ~offer_test_service() {
        offer_thread_.join();
    }

    void offer() {
        app_->offer_service(service_info_.service_id, service_info_.instance_id);
        // this is allowed
        app_->offer_service(service_info_.service_id, service_info_.instance_id);
        // this is not allowed and will be rejected
        app_->offer_service(service_info_.service_id, service_info_.instance_id, 33, 4711);
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

    void run() {
        VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                << service_info_.service_id << "] Running";
        {
            std::unique_lock<std::mutex> its_lock(mutex_);
            while (wait_until_registered_) {
                condition_.wait(its_lock);
            }

            VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                    << service_info_.service_id << "] Offering";
            offer();

            while(wait_until_service_available_) {
                condition_.wait(its_lock);
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
        VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                << service_info_.service_id << "] Calling stop method";
        std::shared_ptr<vsomeip::message> msg(vsomeip::runtime::get()->create_request());
        msg->set_service(service_info_.service_id);
        msg->set_instance(service_info_.instance_id);
        msg->set_method(service_info_.shutdown_method_id);
        msg->set_message_type(vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
        app_->send(msg);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        app_->clear_all_handler();
        app_->stop();
    }

private:
    struct offer_test::service_info service_info_;
    std::shared_ptr<vsomeip::application> app_;

    bool wait_until_registered_;
    bool wait_until_service_available_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::thread offer_thread_;
};

TEST(someip_offer_test, notify_increasing_counter)
{
    offer_test_service its_sample(offer_test::service);
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
