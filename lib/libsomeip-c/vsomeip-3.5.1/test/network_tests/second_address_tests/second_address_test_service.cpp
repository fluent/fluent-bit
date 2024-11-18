// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

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

#include "second_address_test_globals.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class second_address_test_service : public vsomeip_utilities::base_logger {
public:
    second_address_test_service(struct second_address_test::service_info _service_info) :
            vsomeip_utilities::base_logger("SATS", "SECOND ADDRESS TEST SERVICE"),
            service_info_(_service_info),
            app_(vsomeip::runtime::get()->create_application("second_address_test_service")),
            offer_thread_(std::bind(&second_address_test_service::run, this)) {

        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }

        app_->register_state_handler(
                std::bind(&second_address_test_service::on_state, this,
                        std::placeholders::_1));

        app_->register_message_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.request_method_id,
                std::bind(&second_address_test_service::on_message, this,
                        std::placeholders::_1));

        app_->register_message_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.notify_method_id,
                std::bind(&second_address_test_service::on_notify, this,
                        std::placeholders::_1));

        app_->register_message_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.shutdown_method_id,
                std::bind(&second_address_test_service::on_shutdown_method_called, this,
                        std::placeholders::_1));

        app_->register_subscription_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.eventgroup_id,
                std::bind(&second_address_test_service::subscription_handler,
                          this, std::placeholders::_1, std::placeholders::_2,
                          std::placeholders::_3, std::placeholders::_4));

        app_->register_subscription_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.selective_eventgroup_id,
                std::bind(&second_address_test_service::selective_subscription_handler,
                          this, std::placeholders::_1, std::placeholders::_2,
                          std::placeholders::_3, std::placeholders::_4));

        app_->start();
    }

    ~second_address_test_service() {
        offer_thread_.join();
    }

    void stop() {
        app_->stop_offer_service(service_info_.service_id, service_info_.instance_id);
        app_->clear_all_handler();
        app_->stop();
    }

private:
    void on_state(vsomeip::state_type_e _state) {
        VSOMEIP_INFO << "Application " << app_->get_name() << " is "
            << (_state == vsomeip::state_type_e::ST_REGISTERED ?
                    "registered" : "deregistered") << " on service.";

        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_until_registered_ = false;
            condition_.notify_one();
        }
    }

    void on_shutdown_method_called(const std::shared_ptr<vsomeip::message> &_message) {
        app_->send(vsomeip::runtime::get()->create_response(_message));

        VSOMEIP_WARNING << "************************************************************";
        VSOMEIP_WARNING << "Shutdown method called on service -> going down!";
        VSOMEIP_WARNING << "************************************************************";

        std::lock_guard<std::mutex> its_lock(mutex_);
        wait_until_shutdown_method_called_ = false;
        condition_.notify_one();
    }

    void on_message(const std::shared_ptr<vsomeip::message> &_message) {
        EXPECT_EQ(service_info_.service_id, _message->get_service());
        EXPECT_EQ(service_info_.request_method_id, _message->get_method());
        EXPECT_EQ(service_info_.instance_id, _message->get_instance());

        std::shared_ptr<vsomeip::message> response = vsomeip::runtime::get()->create_response(_message);
        response->set_payload(_message->get_payload());
        app_->send(response);

        std::lock_guard<std::mutex> its_lock(mutex_);
        messages_received_++;

        if (messages_received_ == second_address_test::number_of_messages_to_send) {
            wait_until_receive_messages_ = false;
            condition_.notify_one();
        }
    }

    void on_notify(const std::shared_ptr<vsomeip::message> &_message) {
        EXPECT_EQ(service_info_.service_id, _message->get_service());
        EXPECT_EQ(service_info_.notify_method_id, _message->get_method());
        EXPECT_EQ(service_info_.instance_id, _message->get_instance());

        auto its_payload = _message->get_payload();
        notifications_to_send_ = its_payload->get_data()[0];

        std::lock_guard<std::mutex> its_lock(mutex_);
        wait_until_notify_method_called_ = false;
        condition_.notify_one();
    }

    void offer() {
        app_->offer_service(service_info_.service_id, service_info_.instance_id);

        std::set<vsomeip::eventgroup_t> its_eventgroups;
        its_eventgroups.insert(service_info_.eventgroup_id);

        app_->offer_event(service_info_.service_id, service_info_.instance_id,
                service_info_.event_id, its_eventgroups,
                vsomeip::event_type_e::ET_EVENT, std::chrono::milliseconds::zero(),
                false, true, nullptr, vsomeip::reliability_type_e::RT_UNKNOWN);

        its_eventgroups.clear();
        its_eventgroups.insert(service_info_.selective_eventgroup_id);

        app_->offer_event(service_info_.service_id, service_info_.instance_id,
                service_info_.selective_event_id, its_eventgroups,
                vsomeip::event_type_e::ET_SELECTIVE_EVENT, std::chrono::milliseconds::zero(),
                false, true, nullptr, vsomeip::reliability_type_e::RT_UNKNOWN);
    }

    void notify() {
        EXPECT_TRUE(client_subscribed_);
        EXPECT_TRUE(client_subscribed_selective_);
        auto its_payload = vsomeip::runtime::get()->create_payload();

        std::uint32_t i = 0;

        for (; i < notifications_to_send_; i++) {
            its_payload->set_data(std::vector<vsomeip::byte_t>(i+1, 0x55));
            app_->notify(service_info_.service_id, service_info_.instance_id,
                    service_info_.event_id, its_payload);
        }

        for (; i < 2 * notifications_to_send_; i++) {
            its_payload->set_data(std::vector<vsomeip::byte_t>(i+1, 0x55));
            app_->notify_one(service_info_.service_id, service_info_.instance_id,
                    service_info_.selective_event_id, its_payload, client_id_);
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

        while (wait_until_receive_messages_) {
            condition_.wait(its_lock);
        }

        VSOMEIP_DEBUG << "Service waiting for notify method has been called";
        while (wait_until_notify_method_called_) {
            condition_.wait(its_lock);
        }

        VSOMEIP_DEBUG << "Service notifying events";
        notify();

        while (wait_until_shutdown_method_called_) {
            condition_.wait(its_lock);
        }

        its_lock.unlock();
        stop();
    }

    bool subscription_handler(vsomeip::client_t _client, std::uint32_t _uid, std::uint32_t _gid, bool _subscribed) {
        (void)_uid;
        (void)_gid;
        VSOMEIP_DEBUG << __func__ << ": client 0x" << std::hex << std::setw(4) << std::setfill('0') << _client
                << ((_subscribed) ? " subscribed" : "unsubscribed") << " on service.";
        client_subscribed_ = _subscribed;
        return true;
    }

    bool selective_subscription_handler(vsomeip::client_t _client, std::uint32_t _uid, std::uint32_t _gid, bool _subscribed) {
        (void)_uid;
        (void)_gid;
        VSOMEIP_DEBUG << __func__ << ": client 0x" << std::hex << std::setw(4) << std::setfill('0') << _client
                << ((_subscribed) ? " subscribed" : "unsubscribed") << " on service.";
        client_subscribed_selective_ = _subscribed;
        client_id_ = _client;
        return true;
    }

private:
    struct second_address_test::service_info service_info_;
    std::shared_ptr<vsomeip::application> app_;

    bool wait_until_registered_ = true;
    bool wait_until_receive_messages_ = true;
    bool wait_until_notify_method_called_ = true;
    bool wait_until_shutdown_method_called_ = true;
    bool client_subscribed_ = false;
    bool client_subscribed_selective_ = false;
    vsomeip::client_t client_id_ = 0;
    std::uint32_t messages_received_ = 0;
    std::uint8_t notifications_to_send_ = 0;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::thread offer_thread_;
};

TEST(someip_second_address_test, test_communication_with_client)
{
    second_address_test_service its_sample(second_address_test::service);
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
