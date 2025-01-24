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

#include "offer_test_globals.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

static std::string service_number;

class offer_test_service : public vsomeip_utilities::base_logger {
public:
    offer_test_service(struct offer_test::service_info _service_info) :
            vsomeip_utilities::base_logger("OTS1", "OFFER TEST SERVICE"),
            service_info_(_service_info),
            // service with number 1 uses "routingmanagerd" as application name
            // this way the same json file can be reused for all local tests
            // including the ones with routingmanagerd
            app_(vsomeip::runtime::get()->create_application(
                        (service_number == "1") ? "routingmanagerd" :
                                "offer_test_service" + service_number)),
            counter_(0),
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

        // offer field
        std::set<vsomeip::eventgroup_t> its_eventgroups;
        its_eventgroups.insert(service_info_.eventgroup_id);
        app_->offer_event(service_info_.service_id, service_info_.instance_id,
                service_info_.event_id, its_eventgroups,
                vsomeip::event_type_e::ET_EVENT, std::chrono::milliseconds::zero(),
                false, true, nullptr, vsomeip::reliability_type_e::RT_BOTH);

        inc_counter_and_notify();

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

    void on_request(const std::shared_ptr<vsomeip::message> &_message) {
        app_->send(vsomeip::runtime::get()->create_response(_message));
    }

    void on_shutdown_method_called(const std::shared_ptr<vsomeip::message> &_message) {
        (void)_message;
        shutdown_method_called_ = true;
        // this is will trigger a warning
        app_->stop_offer_service(service_info_.service_id, service_info_.instance_id, 44, 4711);
        app_->stop_offer_service(service_info_.service_id, service_info_.instance_id);
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

        VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                << service_info_.service_id << "] Notifying";
        while(!shutdown_method_called_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            inc_counter_and_notify();
        }
    }

    void inc_counter_and_notify() {
        ++counter_;
        // set value to field
        const std::shared_ptr<vsomeip::payload> its_payload(vsomeip::runtime::get()->create_payload());
        std::vector<vsomeip::byte_t> its_data;
        its_data.push_back(static_cast<vsomeip::byte_t>((counter_ & 0xFF000000) >> 24));
        its_data.push_back(static_cast<vsomeip::byte_t>((counter_ & 0xFF0000) >> 16));
        its_data.push_back(static_cast<vsomeip::byte_t>((counter_ & 0xFF00) >> 8));
        its_data.push_back(static_cast<vsomeip::byte_t>((counter_ & 0xFF)));
        its_payload->set_data(its_data);
        app_->notify(service_info_.service_id, service_info_.instance_id,
                service_info_.event_id, its_payload);
    }

private:
    struct offer_test::service_info service_info_;
    std::shared_ptr<vsomeip::application> app_;
    std::uint32_t counter_;

    bool wait_until_registered_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::atomic<bool> shutdown_method_called_;
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
