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

#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>
#include "application_test_globals.hpp"

class application_test_client_availability : public vsomeip_utilities::base_logger {
public:
    application_test_client_availability(struct application_test::service_info _service_info) :
            vsomeip_utilities::base_logger("ATCA", "Application Test Client Availability"),
            service_info_(_service_info),
            app_(vsomeip::runtime::get()->create_application("client")),
            wait_until_registered_(true),
            all_availability_handlers_called_(false),
            run_thread_(std::bind(&application_test_client_availability::run, this)) {
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }
        app_->register_state_handler(
                std::bind(&application_test_client_availability::on_state, this,
                        std::placeholders::_1));

        // register availability handler for every possiblity of
        // ANY_SERVICE, ANY_INSTANCE, ANY_MAJOR, ANY_MINOR
        for (std::uint32_t i = 0; i < 16; i++) {
            vsomeip::service_t its_service = (i & 0x8) ? service_info_.service_id : vsomeip::ANY_SERVICE;
            vsomeip::instance_t its_instance = (i & 0x4) ? service_info_.instance_id : vsomeip::ANY_INSTANCE;
            vsomeip::major_version_t its_major = (i & 0x2) ? service_info_.major_version : vsomeip::ANY_MAJOR;
            vsomeip::minor_version_t its_minor = (i & 0x1) ? service_info_.minor_version : vsomeip::ANY_MINOR;
            app_->register_availability_handler(its_service,
                    its_instance,
                    std::bind(&application_test_client_availability::on_availability, this,
                            std::placeholders::_1, std::placeholders::_2,
                            std::placeholders::_3, i),
                    its_major, its_minor);
            VSOMEIP_DEBUG << "Registering: "
                    << std::setfill('0') << std::hex
                    << std::setw(4) << its_service << "."
                    << std::setw(4) << its_instance << "."
                    << std::setw(2) << (std::uint32_t)its_major << "."
                    << std::setw(4) << its_minor << "."
                    << i;

        }
        app_->register_availability_handler(service_info_.service_id,
                service_info_.instance_id,
                std::bind(&application_test_client_availability::on_availability, this,
                        std::placeholders::_1, std::placeholders::_2,
                        std::placeholders::_3, 16),
                service_info_.major_version, vsomeip::DEFAULT_MINOR);
        VSOMEIP_DEBUG << "Registering: "
                << std::setw(4) << std::setfill('0') << std::hex << service_info_.service_id << "."
                << std::setw(4) << std::setfill('0') << std::hex << service_info_.instance_id << "."
                << std::setw(2) << std::setfill('0') << std::hex << (std::uint32_t)service_info_.service_id << "."
                << std::setw(4) << std::setfill('0') << std::hex << vsomeip::DEFAULT_MINOR << "."
                << 16;
        app_->request_service(service_info_.service_id,
                service_info_.instance_id);
        std::promise<bool> its_promise;
        application_thread_ = std::thread([&](){
            its_promise.set_value(true);
            app_->start();
        });
        EXPECT_TRUE(its_promise.get_future().get());
    }

    ~application_test_client_availability() {
        run_thread_.join();
        application_thread_.join();
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
            vsomeip::instance_t _instance, bool _is_available,
            std::uint32_t _handler_index)
    {
        VSOMEIP_DEBUG<< "Service [" << std::setw(4) << std::setfill('0') << std::hex
                << _service << "." << std::setw(4) << std::setfill('0') << _instance << "] is "
                << (_is_available ? "available." : "NOT available.") << ". "
                << _handler_index;
        if(service_info_.service_id == _service
           && service_info_.instance_id == _instance) {
            std::lock_guard<std::mutex> its_lock(availability_handler_called_mutex_);
            availability_handler_called_[_handler_index] = _is_available;
            availability_condition_.notify_one();
        }
    }

    void run() {
        {
            std::unique_lock<std::mutex> its_lock(mutex_);
            while (wait_until_registered_) {
                condition_.wait(its_lock);
            }
        }
        while(!app_->is_available(service_info_.service_id,
                service_info_.instance_id, service_info_.major_version,
                service_info_.minor_version)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        for (std::uint32_t i = 0; i < 16; i++) {
            vsomeip::service_t its_service = (i & 0x8) ? service_info_.service_id : vsomeip::ANY_SERVICE;
            vsomeip::instance_t its_instance = (i & 0x4) ? service_info_.instance_id : vsomeip::ANY_INSTANCE;
            vsomeip::major_version_t its_major = (i & 0x2) ? service_info_.major_version : vsomeip::ANY_MAJOR;
            vsomeip::minor_version_t its_minor = (i & 0x1) ? service_info_.minor_version : vsomeip::ANY_MINOR;

            VSOMEIP_DEBUG << "Calling is_available: "
                    << std::setw(4) << std::setfill('0') << std::hex << its_service << "."
                    << std::setw(4) << std::setfill('0') << std::hex << its_instance << "."
                    << std::setw(2) << std::setfill('0') << std::hex << (std::uint32_t)its_major << "."
                    << std::setw(4) << std::setfill('0') << std::hex << its_minor;
            EXPECT_TRUE(app_->is_available(its_service, its_instance, its_major, its_minor));

            VSOMEIP_DEBUG << "Calling are_available: "
                    << std::setw(4) << std::setfill('0') << std::hex << its_service << "."
                    << std::setw(4) << std::setfill('0') << std::hex << its_instance << "."
                    << std::setw(2) << std::setfill('0') << std::hex << (std::uint32_t)its_major << "."
                    << std::setw(4) << std::setfill('0') << std::hex << its_minor;
            vsomeip::application::available_t are_available;
            EXPECT_TRUE(app_->are_available(are_available, its_service, its_instance, its_major, its_minor));
            bool found(false);
            auto found_service = are_available.find(service_info_.service_id);
            if(found_service != are_available.end()) {
                auto found_instance = found_service->second.find(service_info_.instance_id);
                if(found_instance != found_service->second.end()) {
                    auto found_major = found_instance->second.find(service_info_.major_version);
                    if (found_major != found_instance->second.end()) {
                        if (found_major->second == service_info_.minor_version) {
                            found = true;
                        }
                    }
                }
            }
            EXPECT_TRUE(found);

        }
        {
            std::unique_lock<std::mutex> its_lock(availability_handler_called_mutex_);
            while(!std::all_of(availability_handler_called_.cbegin(),
                            availability_handler_called_.cend(),
                            [&](const availability_handler_called_t::value_type &v) {
                                return v;
                            })) {
                availability_condition_.wait(its_lock);
            }
        }
        VSOMEIP_INFO << " Everything is available";
        all_availability_handlers_called_ = true;
    }

    void stop() {
        VSOMEIP_INFO << "going down";
        app_->clear_all_handler();
        app_->stop();
    }

    bool all_availability_handlers_called() const {
        return all_availability_handlers_called_;
    }

private:
    struct application_test::service_info service_info_;
    std::shared_ptr<vsomeip::application> app_;
    std::mutex availability_handler_called_mutex_;
    std::condition_variable availability_condition_;
    typedef std::array<bool, 17> availability_handler_called_t;
    availability_handler_called_t availability_handler_called_;


    bool wait_until_registered_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::atomic<bool> all_availability_handlers_called_;
    std::thread run_thread_;
    std::thread application_thread_;
};
