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

class offer_test_big_sd_msg_client : public vsomeip_utilities::base_logger {
public:
    offer_test_big_sd_msg_client(struct offer_test::service_info _service_info) :
            vsomeip_utilities::base_logger("OTBC", "OFFER TEST BIG SD MSG CLIENT"),
            service_info_(_service_info),
            app_(vsomeip::runtime::get()->create_application("offer_test_big_sd_msg_client")),
            wait_until_registered_(true),
            wait_until_service_available_(true),
            wait_until_subscribed_(true),
            wait_for_stop_(true),
            stop_thread_(std::bind(&offer_test_big_sd_msg_client::wait_for_stop, this)),
            send_thread_(std::bind(&offer_test_big_sd_msg_client::send, this)) {
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }
        app_->register_state_handler(
                std::bind(&offer_test_big_sd_msg_client::on_state, this,
                        std::placeholders::_1));

        app_->register_message_handler(vsomeip::ANY_SERVICE,
                vsomeip::ANY_INSTANCE, vsomeip::ANY_METHOD,
                std::bind(&offer_test_big_sd_msg_client::on_message, this,
                        std::placeholders::_1));

        // register availability for all other services and request their event.
        app_->register_availability_handler(vsomeip::ANY_SERVICE,
                vsomeip::ANY_INSTANCE,
                std::bind(&offer_test_big_sd_msg_client::on_availability, this,
                        std::placeholders::_1, std::placeholders::_2,
                        std::placeholders::_3), 0x1, 0x1);
        std::set<vsomeip::eventgroup_t> its_eventgroups;
        its_eventgroups.insert(offer_test::big_msg_eventgroup_id);
        for (std::uint16_t s = 1; s <= offer_test::big_msg_number_services; s++) {
            app_->request_service(s,0x1,0x1,0x1);
            app_->request_event(s,0x1, offer_test::big_msg_event_id,
                    its_eventgroups, vsomeip::event_type_e::ET_EVENT,
                    vsomeip::reliability_type_e::RT_UNKNOWN);
            app_->subscribe(s, 0x1,offer_test::big_msg_eventgroup_id, 0x1,
                    offer_test::big_msg_event_id);
            services_available_subribed_[s] = std::make_pair(false,0);
            app_->register_subscription_status_handler(s,0x1,
                    offer_test::big_msg_eventgroup_id,
                    offer_test::big_msg_event_id,
                    std::bind(&offer_test_big_sd_msg_client::subscription_status_changed, this,
                              std::placeholders::_1, std::placeholders::_2,
                              std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));
        }
        app_->start();
    }

    ~offer_test_big_sd_msg_client() {
        send_thread_.join();
        stop_thread_.join();
    }

    void on_state(vsomeip::state_type_e _state) {
        VSOMEIP_WARNING << "Application " << app_->get_name() << " is "
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
            VSOMEIP_DEBUG << "Service [" << std::setw(4)
            << std::setfill('0') << std::hex << _service << "." << _instance
            << "] is " << (_is_available ? "available":"not available") << ".";

            std::lock_guard<std::mutex> its_lock(mutex_);
            if(_is_available) {
                auto found_service = services_available_subribed_.find(_service);
                if (found_service != services_available_subribed_.end()) {
                    found_service->second.first = true;
                    if (std::all_of(services_available_subribed_.cbegin(),
                                    services_available_subribed_.cend(),
                                    [](const services_available_subribed_t::value_type& v) {
                                        return v.second.first;
                                    }
                    )) {
                        VSOMEIP_WARNING << "************************************************************";
                        VSOMEIP_WARNING << "All services available!";
                        VSOMEIP_WARNING << "************************************************************";
                        wait_until_service_available_ = false;
                        condition_.notify_one();
                    }
                }
            }
    }

    void subscription_status_changed(const vsomeip::service_t _service,
                                     const vsomeip::instance_t _instance,
                                     const vsomeip::eventgroup_t _eventgroup,
                                     const vsomeip::event_t _event,
                                     const uint16_t _error) {
        EXPECT_EQ(0x1, _instance);
        EXPECT_EQ(offer_test::big_msg_eventgroup_id, _eventgroup);
        EXPECT_EQ(offer_test::big_msg_event_id, _event);
        VSOMEIP_DEBUG << "Service [" << std::setw(4)
        << std::setfill('0') << std::hex << _service << "." << _instance
        << "] has " << (!_error ? "sent subscribe ack":" sent subscribe_nack") << ".";
        if (_error == 0x0 /*OK*/) {

            std::lock_guard<std::mutex> its_lock(mutex_);
            auto found_service = services_available_subribed_.find(_service);
            if (found_service != services_available_subribed_.end()) {
                found_service->second.second++;
                if (found_service->second.second > 1) {
                    ADD_FAILURE() << "Registered subscription status handler was "
                            "called " << std::dec << found_service->second.second
                            << " times for service: " << std::hex
                            << found_service->first;
                }
                if (std::all_of(services_available_subribed_.cbegin(),
                                services_available_subribed_.cend(),
                                [](const services_available_subribed_t::value_type& v) {
                                    return v.second.second == 1;
                                }
                )) {
                    VSOMEIP_WARNING << "************************************************************";
                    VSOMEIP_WARNING << "All subscription were acknowledged!";
                    VSOMEIP_WARNING << "************************************************************";
                    wait_until_subscribed_ = false;
                    condition_.notify_one();
                }
            }
        }
    };

    void on_message(const std::shared_ptr<vsomeip::message> &_message) {
        if (_message->get_message_type() == vsomeip::message_type_e::MT_RESPONSE) {
            on_response(_message);
        }
    }

    void on_response(const std::shared_ptr<vsomeip::message> &_message) {
        EXPECT_EQ(0x1, _message->get_service());
        EXPECT_EQ(service_info_.shutdown_method_id, _message->get_method());
        EXPECT_EQ(0x1, _message->get_instance());
        if(service_info_.shutdown_method_id == _message->get_method()) {
            std::lock_guard<std::mutex> its_lock(stop_mutex_);
            wait_for_stop_ = false;
            VSOMEIP_INFO << "going down";
            stop_condition_.notify_one();
        }
    }

    void send() {
        std::unique_lock<std::mutex> its_lock(mutex_);
        while (wait_until_registered_) {
            condition_.wait(its_lock);
        }

        while (wait_until_service_available_) {
            condition_.wait(its_lock);
        }

        while (wait_until_subscribed_) {
            condition_.wait(its_lock);
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
        std::shared_ptr<vsomeip::message> its_req = vsomeip::runtime::get()->create_request();
        its_req->set_service(1);
        its_req->set_instance(1);
        its_req->set_interface_version(0x1);
        its_req->set_method(service_info_.shutdown_method_id);
        app_->send(its_req);
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
    std::shared_ptr<vsomeip::application> app_;

    bool wait_until_registered_;
    bool wait_until_service_available_;
    bool wait_until_subscribed_;
    std::mutex mutex_;
    std::condition_variable condition_;

    bool wait_for_stop_;
    std::mutex stop_mutex_;
    std::condition_variable stop_condition_;

    typedef std::map<vsomeip::service_t,std::pair<bool, std::uint32_t>> services_available_subribed_t;
    services_available_subribed_t services_available_subribed_;
    std::thread stop_thread_;
    std::thread send_thread_;
};

TEST(someip_offer_test_big_sd_msg, subscribe_or_call_method_at_service)
{
    offer_test_big_sd_msg_client its_sample(offer_test::service);
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
