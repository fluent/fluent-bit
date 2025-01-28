// Copyright (C) 2014-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <chrono>
#include <condition_variable>
#include <iomanip>
#include <thread>
#include <mutex>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#include <gtest/gtest.h>

#include "climate_test_globals.hpp"

class service_sample {
public:
    service_sample(struct climate_test::service_info _service_info) :
            app_(vsomeip::runtime::get()->create_application()),
            blocked_(false),
            running_(true),
            is_offered_(false),
            is_second_(false),
            offer_thread_(std::bind(&service_sample::run, this)),
            notify_thread_(std::bind(&service_sample::notify, this)),
            service_info_(_service_info) {
    }

    bool init() {
        std::lock_guard<std::mutex> its_lock(mutex_);

        if (!app_->init()) {
            std::cerr << "Couldn't initialize application" << std::endl;
            return false;
        }
        app_->register_state_handler(
                std::bind(&service_sample::on_state, this,
                        std::placeholders::_1));

        app_->register_message_handler(
                service_info_.service_id,
                service_info_.instance_id,
                service_info_.get_method_id,
                std::bind(&service_sample::on_message, this,
                          std::placeholders::_1));

        app_->register_message_handler(
                service_info_.service_id,
                service_info_.instance_id,
                service_info_.shutdown_method_id,
                std::bind(&service_sample::on_shutdown_message, this,
                          std::placeholders::_1));

        std::set<vsomeip::eventgroup_t> its_groups;
        its_groups.insert(service_info_.eventgroup_id);
        app_->offer_event(
                service_info_.service_id,
                service_info_.instance_id,
                service_info_.event_id,
                its_groups,
                vsomeip::event_type_e::ET_FIELD, std::chrono::milliseconds::zero(),
                false, true, nullptr, vsomeip::reliability_type_e::RT_UNKNOWN);
        {
            std::lock_guard<std::mutex> its_lock(payload_mutex_);
            payload_ = vsomeip::runtime::get()->create_payload();
        }

        blocked_ = true;
        condition_.notify_one();
        return true;
    }

    void start() {
        app_->start();
    }

    void stop() {
        {
            std::lock_guard<std::mutex> its_lock_notify(notify_mutex_);
            running_ = false;
            notify_condition_.notify_one();
        }
        app_->clear_all_handler();
        if (std::this_thread::get_id() != offer_thread_.get_id()) {
            if (offer_thread_.joinable()) {
                offer_thread_.join();
            }
        } else {
            offer_thread_.detach();
        }
        if (std::this_thread::get_id() != notify_thread_.get_id()) {
            if (notify_thread_.joinable()) {
                notify_thread_.join();
            }
        } else {
            notify_thread_.detach();
        }
        app_->stop();
    }

    void offer() {
        std::lock_guard<std::mutex> its_lock(notify_mutex_);
        app_->offer_service(service_info_.service_id, service_info_.instance_id);
        is_offered_ = true;
        notify_condition_.notify_one();
    }

    void stop_offer() {
        std::lock_guard<std::mutex> its_lock(notify_mutex_);
        app_->stop_offer_service(service_info_.service_id, service_info_.instance_id);
        is_offered_ = false;
        notify_condition_.notify_one();
    }

    void on_state(vsomeip::state_type_e _state) {
        std::cout << "Application " << app_->get_name() << " is "
        << (_state == vsomeip::state_type_e::ST_REGISTERED ?
                "registered." : "deregistered.") << std::endl;
    }

    void on_message(const std::shared_ptr<vsomeip::message> &_message) {
        // Triger second part of the test, offer and stop offer service
        (void)_message;
        stop_offer();
        std::this_thread::sleep_for(climate_test::OFFER_CYCLE_INTERVAL);
        std::lock_guard<std::mutex> its_lock(message_mutex_);
        is_second_ = true;
        notify_condition_.notify_one();
    }

    void on_shutdown_message(const std::shared_ptr<vsomeip::message> &_message) {
        // Test concluded, stop the service
        (void)_message;
        stop_offer();
        stop();
    }

    void run() {
        std::unique_lock<std::mutex> its_lock(mutex_);
        while (!blocked_)
            condition_.wait(its_lock);

        offer();
        std::unique_lock<std::mutex> its_lock_message(message_mutex_);
        while (running_ && !is_second_) {
            notify_condition_.wait(its_lock_message);
        }

        // Offer and stop offer service with 1 second interval
        bool is_offer(true);
        for (uint8_t i = 0; i < 3; ++i) {
            if (is_offer) {
                offer();
            }
            else {
                stop_offer();
            }
            is_offer = !is_offer;
            std::this_thread::sleep_for(climate_test::OFFER_CYCLE_INTERVAL);
        }
    }

    void notify() {

        vsomeip::byte_t its_data[]{ 0x00, 0x01, 0x02, 0x03, 0x04};
        uint32_t its_size = 5;

        while (running_) {
            std::unique_lock<std::mutex> its_lock(notify_mutex_);
            while (!is_offered_ && running_) {
                notify_condition_.wait(its_lock);
            }
            while (is_offered_ && running_) {
                {
                    std::lock_guard<std::mutex> its_lock(payload_mutex_);
                    payload_->set_data(its_data, its_size);

                    VSOMEIP_INFO << "\nSERVICE SIDE -> " << "Setting event (Length=" << std::dec << its_size << ")." << std::endl;
                    app_->notify(service_info_.service_id, service_info_.instance_id, service_info_.event_id, payload_);
                }

                notify_condition_.wait_for(its_lock, std::chrono::seconds(climate_test::OFFER_CYCLE_INTERVAL));
            }
        }
    }

private:
    std::shared_ptr<vsomeip::application> app_;

    std::mutex mutex_;
    std::condition_variable condition_;
    bool blocked_;
    bool running_;

    std::mutex notify_mutex_;
    std::condition_variable notify_condition_;
    bool is_offered_;

    std::mutex message_mutex_;
    bool is_second_;

    std::mutex payload_mutex_;
    std::shared_ptr<vsomeip::payload> payload_;

    // blocked_ / is_offered_ must be initialized before starting the threads!
    std::thread offer_thread_;
    std::thread notify_thread_;

    struct climate_test::service_info service_info_;
};


TEST(someip_subscribe_notify_test_example, run_service)
{
    service_sample its_sample(climate_test::service);

    if (its_sample.init()) {
        its_sample.start();
    }
}


#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
