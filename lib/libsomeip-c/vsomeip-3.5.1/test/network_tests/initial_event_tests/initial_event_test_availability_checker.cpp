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

#include "initial_event_test_globals.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class initial_event_test_availability_checker : public vsomeip_utilities::base_logger {
public:
    initial_event_test_availability_checker(int _client_number,
                              std::array<initial_event_test::service_info, 7> _service_infos) :
            vsomeip_utilities::base_logger("IETC", "INITIAL EVENT TEST AVAILABILITY CHECKER"),
            client_number_(_client_number),
            service_infos_(_service_infos),
            app_(vsomeip::runtime::get()->create_application()),
            wait_until_registered_(true),
            wait_for_stop_(true),
            stop_thread_(std::bind(&initial_event_test_availability_checker::wait_for_stop, this)) {
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }
        app_->register_state_handler(
                std::bind(&initial_event_test_availability_checker::on_state, this,
                        std::placeholders::_1));

        // register availability for all other services and request their event.
        for(const auto& i : service_infos_) {
            if (i.service_id == 0xFFFF && i.instance_id == 0xFFFF) {
                continue;
            }
            other_services_available_[std::make_pair(i.service_id, i.instance_id)] = false;
            app_->register_availability_handler(i.service_id, i.instance_id,
                    std::bind(&initial_event_test_availability_checker::on_availability, this,
                            std::placeholders::_1, std::placeholders::_2,
                            std::placeholders::_3));
            app_->request_service(i.service_id, i.instance_id);
        }

        app_->start();
    }

    ~initial_event_test_availability_checker() {
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
        if(_is_available) {
            auto its_service = other_services_available_.find(std::make_pair(_service, _instance));
            if(its_service != other_services_available_.end()) {
                if(its_service->second != _is_available) {
                its_service->second = true;
                VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                        << client_number_ << "] Service ["
                << std::setw(4) << std::setfill('0') << std::hex << _service << "." << _instance
                << "] is available.";

                }
            }

            if(std::all_of(other_services_available_.cbegin(),
                           other_services_available_.cend(),
                           [](const std::map<std::pair<vsomeip::service_t,
                                   vsomeip::instance_t>, bool>::value_type& v) {
                                return v.second;})) {

                std::lock_guard<std::mutex> its_lock(stop_mutex_);
                wait_for_stop_ = false;
                stop_condition_.notify_one();
            }
        }
    }

    void wait_for_stop() {
        std::unique_lock<std::mutex> its_lock(stop_mutex_);
        while (wait_for_stop_) {
            stop_condition_.wait(its_lock);
        }
        VSOMEIP_INFO << "[" << std::setw(4) << std::setfill('0') << std::hex
                << client_number_ << "] all services are available. Going down";
        app_->clear_all_handler();
        app_->stop();
    }

private:
    int client_number_;
    std::array<initial_event_test::service_info, 7> service_infos_;
    std::shared_ptr<vsomeip::application> app_;
    std::map<std::pair<vsomeip::service_t, vsomeip::instance_t>, bool> other_services_available_;

    bool wait_until_registered_;
    std::mutex mutex_;
    std::condition_variable condition_;

    bool wait_for_stop_;
    std::mutex stop_mutex_;
    std::condition_variable stop_condition_;
    std::thread stop_thread_;
};

static int client_number;
static bool use_same_service_id;

TEST(someip_initial_event_test, wait_for_availability_and_exit)
{
    if(use_same_service_id) {
        initial_event_test_availability_checker its_sample(client_number,
                initial_event_test::service_infos_same_service_id);
    } else {
        initial_event_test_availability_checker its_sample(client_number,
                initial_event_test::service_infos);
    }
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    if(argc < 2) {
        std::cerr << "Please specify a client number and subscription type, like: " << argv[0] << " 2 SAME_SERVICE_ID" << std::endl;
        std::cerr << "Valid client numbers are from 0 to 0xFFFF" << std::endl;
        std::cerr << "If SAME_SERVICE_ID is specified as third parameter the test is run w/ multiple instances of the same service" << std::endl;
        return 1;
    }

    client_number = std::stoi(std::string(argv[1]), nullptr);

    if (argc >= 2) {
        for (int i = 2; i < argc; i++) {
            if (std::string("SAME_SERVICE_ID") == std::string(argv[i])) {
                use_same_service_id = true;
                std::cout << "Availability checker: Using same service ID" << std::endl;
            }
        }
    }
    return RUN_ALL_TESTS();
}
#endif
