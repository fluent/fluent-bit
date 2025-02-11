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


class initial_event_test_service : public vsomeip_utilities::base_logger {
public:
    initial_event_test_service(struct initial_event_test::service_info _service_info,
                               std::uint32_t _events_to_offer, vsomeip::reliability_type_e _reliability_type) :
            vsomeip_utilities::base_logger("IETS", "INITIAL EVENT TEST SERVICE"),
            service_info_(_service_info),
            app_(vsomeip::runtime::get()->create_application()),
            wait_until_registered_(true),
            events_to_offer_(_events_to_offer),
            offer_thread_(std::bind(&initial_event_test_service::run, this)),
            reliability_type_(_reliability_type) {
        if (!app_->init()) {
            offer_thread_.detach();
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }
        app_->register_state_handler(
                std::bind(&initial_event_test_service::on_state, this,
                        std::placeholders::_1));

        // offer field
        std::set<vsomeip::eventgroup_t> its_eventgroups;
        its_eventgroups.insert(service_info_.eventgroup_id);
        for (std::uint16_t i = 0; i < events_to_offer_; i++) {
            app_->offer_event(service_info_.service_id, service_info_.instance_id,
                    static_cast<vsomeip::event_t>(service_info_.event_id + i),
                    its_eventgroups, vsomeip::event_type_e::ET_FIELD,
                    std::chrono::milliseconds::zero(), false, true, nullptr,
                    reliability_type_);
        }

        // set value to field
        std::shared_ptr<vsomeip::payload> its_payload =
                vsomeip::runtime::get()->create_payload();
        vsomeip::byte_t its_data[2] = {static_cast<vsomeip::byte_t>((service_info_.service_id & 0xFF00) >> 8),
                static_cast<vsomeip::byte_t>((service_info_.service_id & 0xFF))};
        its_payload->set_data(its_data, 2);
        for (std::uint16_t i = 0; i < events_to_offer_; i++) {
            app_->notify(service_info_.service_id, service_info_.instance_id,
                    static_cast<vsomeip::event_t>(service_info_.event_id + i), its_payload);
        }

        app_->start();
    }

    ~initial_event_test_service() {
    	app_->stop();

        if (offer_thread_.joinable()) {
            offer_thread_.join();
        }
    }

    void offer() {
        app_->offer_service(service_info_.service_id, service_info_.instance_id);
    }

    void on_state(vsomeip::state_type_e _state) {
        VSOMEIP_INFO << "Application " << app_->get_name() << " is "
        << (_state == vsomeip::state_type_e::ST_REGISTERED ?
                "registered." : "deregistered.");

        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            {
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_until_registered_ = false;
            }
            condition_.notify_one();
        }
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
    }

private:
    initial_event_test::service_info service_info_;
    std::shared_ptr<vsomeip::application> app_;

    bool wait_until_registered_;
    std::uint32_t events_to_offer_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::thread offer_thread_;
    vsomeip::reliability_type_e reliability_type_;
};

static unsigned long service_number;
static bool use_same_service_id;
static std::uint32_t offer_multiple_events;
vsomeip::reliability_type_e reliability_type = vsomeip::reliability_type_e::RT_UNKNOWN;

TEST(someip_initial_event_test, set_field_once)
{
    if(use_same_service_id) {
        initial_event_test_service its_sample(
                initial_event_test::service_infos_same_service_id[service_number], offer_multiple_events,
                reliability_type);
    } else {
        initial_event_test_service its_sample(
                initial_event_test::service_infos[service_number], offer_multiple_events,
                reliability_type);
    }
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    if(argc < 2) {
        std::cerr << "Please specify a service number and subscription type, like: " << argv[0] << " 2 SAME_SERVICE_ID" << std::endl;
        std::cerr << "Valid service numbers are in the range of [1,6]" << std::endl;
        std::cerr << "After the service number one/multiple of these flags can be specified:";
        std::cerr << " - SAME_SERVICE_ID flag. If set the test is run w/ multiple instances of the same service, default false" << std::endl;
        std::cerr << " - MULTIPLE_EVENTS flag. If set the test will offer to multiple events in the eventgroup, default false" << std::endl;
        return 1;
    }

    service_number = std::stoul(std::string(argv[1]), nullptr);

    offer_multiple_events = 1;
    use_same_service_id = false;

    if (argc > 2) {
        for (int i = 2; i < argc; i++) {
            if (std::string("SAME_SERVICE_ID") == std::string(argv[i])) {
                use_same_service_id = true;
                std::cout << "Using same service ID" << std::endl;
            } else if (std::string("MULTIPLE_EVENTS") == std::string(argv[i])) {
                offer_multiple_events = 5;
            }  else if (std::string("TCP")== std::string(argv[i])) {
                reliability_type = vsomeip::reliability_type_e::RT_RELIABLE;
                std::cout << "Using reliability type RT_RELIABLE" << std::endl;
            } else if (std::string("UDP")== std::string(argv[i])) {
                reliability_type = vsomeip::reliability_type_e::RT_UNRELIABLE;
                std::cout << "Using reliability type RT_UNRELIABLE" << std::endl;
            } else if (std::string("TCP_AND_UDP")== std::string(argv[i])) {
                reliability_type = vsomeip::reliability_type_e::RT_BOTH;
                std::cout << "Using reliability type RT_BOTH" << std::endl;
            }
        }
    }
    return RUN_ALL_TESTS();
}
#endif
