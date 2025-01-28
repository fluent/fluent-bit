// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include <cmath> // for isfinite
#include <condition_variable>
#include <functional>
#include <iomanip>
#include <mutex>
#include <numeric>
#include <thread>

#include "cpu_load_test_globals.hpp"
#include <vsomeip/internal/logger.hpp>
#include "cpu_load_measurer.hpp"

// for getpid
#include <sys/types.h>
#include <unistd.h>

class cpu_load_test_service
{
public:
    cpu_load_test_service() :
                    app_(vsomeip::runtime::get()->create_application("cpu_load_test_service")),
                    is_registered_(false),
                    blocked_(false),
                    number_of_received_messages_(0),
                    number_of_received_messages_total_(0),
                    load_measurer_(static_cast<std::uint32_t>(::getpid())),
                    offer_thread_(std::bind(&cpu_load_test_service::run, this))
    {
    }

    ~cpu_load_test_service() {
        {
            std::lock_guard<std::mutex> its_lock(mutex_);
            blocked_ = true;
            condition_.notify_one();
        }
        offer_thread_.join();
    }

    bool init()
    {
        std::lock_guard<std::mutex> its_lock(mutex_);

        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return false;
        }
        app_->register_message_handler(cpu_load_test::service_id,
                cpu_load_test::instance_id, cpu_load_test::method_id,
                std::bind(&cpu_load_test_service::on_message, this,
                        std::placeholders::_1));

        app_->register_message_handler(cpu_load_test::service_id,
                cpu_load_test::instance_id, cpu_load_test::method_id_shutdown,
                std::bind(&cpu_load_test_service::on_message_shutdown, this,
                        std::placeholders::_1));
        app_->register_message_handler(cpu_load_test::service_id,
                cpu_load_test::instance_id, cpu_load_test::method_id_cpu_measure_start,
                std::bind(&cpu_load_test_service::on_message_start_measuring, this,
                        std::placeholders::_1));
        app_->register_message_handler(cpu_load_test::service_id,
                cpu_load_test::instance_id, cpu_load_test::method_id_cpu_measure_stop,
                std::bind(&cpu_load_test_service::on_message_stop_measuring, this,
                        std::placeholders::_1));
        app_->register_state_handler(
                std::bind(&cpu_load_test_service::on_state, this,
                        std::placeholders::_1));
        return true;
    }

    void start()
    {
        VSOMEIP_INFO << "Starting...";
        app_->start();
    }

    void stop()
    {
        VSOMEIP_INFO << "Stopping...";
        app_->stop_offer_service(cpu_load_test::service_id, cpu_load_test::instance_id);
        app_->clear_all_handler();
        app_->stop();
    }

    void on_state(vsomeip::state_type_e _state)
    {
        VSOMEIP_INFO << "Application " << app_->get_name() << " is "
                << (_state == vsomeip::state_type_e::ST_REGISTERED ? "registered." :
                        "deregistered.");

        if(_state == vsomeip::state_type_e::ST_REGISTERED)
        {
            if(!is_registered_)
            {
                is_registered_ = true;
                std::lock_guard<std::mutex> its_lock(mutex_);
                blocked_ = true;
                // "start" the run method thread
                condition_.notify_one();
            }
        }
        else
        {
            is_registered_ = false;
        }
    }

    void on_message(const std::shared_ptr<vsomeip::message>& _request)
    {
        number_of_received_messages_++;
        number_of_received_messages_total_++;
        // send response
        app_->send(vsomeip::runtime::get()->create_response(_request));
    }

    void on_message_start_measuring(const std::shared_ptr<vsomeip::message>& _request)
    {
        (void)_request;
        load_measurer_.start();
    }

    void on_message_stop_measuring(const std::shared_ptr<vsomeip::message>& _request)
    {
        (void)_request;
        load_measurer_.stop();
        VSOMEIP_DEBUG << "Received " << std::setw(4) << std::setfill('0')
        << number_of_received_messages_ << " messages. CPU load [%]: "
        << std::fixed << std::setprecision(2)
        << (std::isfinite(load_measurer_.get_cpu_load()) ? load_measurer_.get_cpu_load() : 0.0);
        results_.push_back(std::isfinite(load_measurer_.get_cpu_load()) ? load_measurer_.get_cpu_load() : 0.0);
        number_of_received_messages_ = 0;
    }

    void on_message_shutdown(
            const std::shared_ptr<vsomeip::message>& _request)
    {
        (void)_request;
        VSOMEIP_INFO << "Shutdown method was called, going down now.";
        const double average_load(std::accumulate(results_.begin(), results_.end(), 0.0) / static_cast<double>(results_.size()));
        VSOMEIP_INFO << "Received: " << number_of_received_messages_total_
            << " in total (excluding control messages). This caused: "
            << std::fixed << std::setprecision(2)
            << average_load << "% load in average (average of "
            << results_.size() << " measurements).";

        std::vector<double> results_no_zero;
        for(const auto &v : results_) {
            if(v > 0.0) {
                results_no_zero.push_back(v);
            }
        }
        const double average_load_no_zero(std::accumulate(results_no_zero.begin(), results_no_zero.end(), 0.0) / static_cast<double>(results_no_zero.size()));
        VSOMEIP_INFO << "Sent: " << number_of_received_messages_total_
            << " messages in total (excluding control messages). This caused: "
            << std::fixed << std::setprecision(2)
            << average_load_no_zero << "% load in average, if measured cpu load "
            << "was greater zero (average of "
            << results_no_zero.size() << " measurements).";
        stop();
    }

    void run()
    {
        std::unique_lock<std::mutex> its_lock(mutex_);
        while (!blocked_) {
            condition_.wait(its_lock);
        }

        app_->offer_service(cpu_load_test::service_id, cpu_load_test::instance_id);
    }

private:
    std::shared_ptr<vsomeip::application> app_;
    bool is_registered_;

    std::mutex mutex_;
    std::condition_variable condition_;
    bool blocked_;
    std::uint32_t number_of_received_messages_;
    std::uint32_t number_of_received_messages_total_;
    cpu_load_measurer load_measurer_;
    std::vector<double> results_;
    std::thread offer_thread_;
};


TEST(someip_payload_test, DISABLED_send_response_for_every_request)
{
    cpu_load_test_service test_service;
    if (test_service.init()) {
        test_service.start();
    }
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
