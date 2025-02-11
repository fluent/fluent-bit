// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <thread>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#include "event_test_globals.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class event_test_service : public vsomeip_utilities::base_logger {
public:
    event_test_service(struct event_test::service_info _service_info, bool _use_tcp) :
            vsomeip_utilities::base_logger("EVTS", "EVENT TEST SERVICE"),
            service_info_(_service_info),
            test_mode_(event_test::test_mode_e::UNKNOWN),
            app_(vsomeip::runtime::get()->create_application("event_test_service")),
            wait_until_registered_(true),
            wait_until_notify_method_called_(true),
            wait_until_shutdown_method_called_(true),
            client_subscribed_(false),
            notifications_to_send_(0),
            offer_thread_(std::bind(&event_test_service::run, this)),
            use_tcp_(_use_tcp) {
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }
        app_->register_state_handler(
                std::bind(&event_test_service::on_state, this,
                        std::placeholders::_1));

        std::set<vsomeip::eventgroup_t> its_eventgroups;
        its_eventgroups.insert(_service_info.eventgroup_id);
        app_->offer_event(service_info_.service_id, service_info_.instance_id,
                    service_info_.event_id, its_eventgroups,
                    vsomeip::event_type_e::ET_EVENT, std::chrono::milliseconds::zero(),
                    false, true, nullptr,
                    (use_tcp_ ? vsomeip::reliability_type_e::RT_RELIABLE : vsomeip::reliability_type_e::RT_UNRELIABLE));
        app_->register_message_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.shutdown_method_id,
                std::bind(&event_test_service::on_shutdown_method_called, this,
                        std::placeholders::_1));
        app_->register_message_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.notify_method_id,
                std::bind(&event_test_service::on_message, this,
                        std::placeholders::_1));
        app_->register_subscription_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.eventgroup_id,
                std::bind(&event_test_service::subscription_handler,
                          this, std::placeholders::_1, std::placeholders::_2,
                          std::placeholders::_3, std::placeholders::_4));

        app_->start();
    }

    ~event_test_service() {
        offer_thread_.join();
    }

    void offer() {
        app_->offer_service(service_info_.service_id, service_info_.instance_id);
    }

    void stop() {
        app_->stop_offer_service(service_info_.service_id, service_info_.instance_id);
        app_->clear_all_handler();
        app_->stop();
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

    void on_shutdown_method_called(const std::shared_ptr<vsomeip::message> &_message) {
        app_->send(vsomeip::runtime::get()->create_response(_message));
        VSOMEIP_WARNING << "************************************************************";
        VSOMEIP_WARNING << "Shutdown method called -> going down!";
        VSOMEIP_WARNING << "************************************************************";
        std::lock_guard<std::mutex> its_lock(mutex_);
        wait_until_shutdown_method_called_ = false;
        condition_.notify_one();
    }

    void on_message(const std::shared_ptr<vsomeip::message> &_message) {
        EXPECT_EQ(service_info_.service_id, _message->get_service());
        EXPECT_EQ(service_info_.instance_id, _message->get_instance());
        EXPECT_EQ(service_info_.notify_method_id, _message->get_method());
        auto its_payload = _message->get_payload();
        ASSERT_EQ(2u, its_payload->get_length());
        test_mode_ = static_cast<event_test::test_mode_e>(its_payload->get_data()[0]);
        notifications_to_send_ = static_cast<std::uint32_t>(its_payload->get_data()[1]);
        std::lock_guard<std::mutex> its_lock(mutex_);
        wait_until_notify_method_called_ = false;
        condition_.notify_one();
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

        while (wait_until_notify_method_called_) {
            condition_.wait(its_lock);
        }
        VSOMEIP_INFO << "notify";
        notify();


        while (wait_until_shutdown_method_called_) {
            condition_.wait(its_lock);
        }
        its_lock.unlock();
        stop();
    }

    void notify() {
        EXPECT_TRUE(client_subscribed_);
        auto its_payload = vsomeip::runtime::get()->create_payload();
        for (std::uint32_t i = 0; i < notifications_to_send_; i++) {
            if (test_mode_ == event_test::test_mode_e::PAYLOAD_FIXED) {
                its_payload->set_data(std::vector<vsomeip::byte_t>(event_test::payload_fixed_length, 0x44));
            } else if (test_mode_ == event_test::test_mode_e::PAYLOAD_DYNAMIC) {
                its_payload->set_data(std::vector<vsomeip::byte_t>(i+1, 0x55));
            }
            app_->notify(service_info_.service_id, service_info_.instance_id,
                    service_info_.event_id, its_payload, false);
        }
    }

    bool subscription_handler(vsomeip::client_t _client, std::uint32_t _uid, std::uint32_t _gid, bool _subscribed) {
        (void)_uid;
        (void)_gid;
        VSOMEIP_INFO << __func__ << ": client: 0x" << std::hex << _client
                << ((_subscribed) ? " subscribed" : "unsubscribed");
        client_subscribed_ = _subscribed;
        return true;
    }

private:
    struct event_test::service_info service_info_;
    event_test::test_mode_e test_mode_;
    std::shared_ptr<vsomeip::application> app_;

    bool wait_until_registered_;
    bool wait_until_notify_method_called_;
    bool wait_until_shutdown_method_called_;
    std::atomic<bool> client_subscribed_;
    std::uint32_t notifications_to_send_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::thread offer_thread_;
    bool use_tcp_;
};

static bool use_tcp = false;

TEST(someip_event_test, send_events)
{
    event_test_service its_sample(event_test::service, use_tcp);
}


#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);

    if (std::string("TCP")== std::string(argv[1])) {
        use_tcp = true;
    } else if (std::string("UDP")== std::string(argv[1])) {
        use_tcp = false;
    }

    return RUN_ALL_TESTS();
}
#endif
