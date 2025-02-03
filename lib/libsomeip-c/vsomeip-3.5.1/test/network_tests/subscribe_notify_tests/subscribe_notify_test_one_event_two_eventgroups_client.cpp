// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
#include <csignal>
#endif
#include <chrono>
#include <condition_variable>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>
#include <utility>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#include <gtest/gtest.h>

#include "subscribe_notify_test_globals.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class subscribe_notify_test_one_event_two_eventgroups_client : public vsomeip_utilities::base_logger {
public:
    subscribe_notify_test_one_event_two_eventgroups_client(
            struct subscribe_notify_test::service_info _info, bool _use_tcp) :
            vsomeip_utilities::base_logger("SNC1", "SUBSCRIBE NOTIFY TEST ONE EVENT TWO EVENTGROUPS CLIENT"),
            app_(
                    vsomeip::runtime::get()->create_application(
                            "subscribe_notify_test_client")),
            info_(_info),
            use_tcp_(_use_tcp),
            wait_availability_(true),
            wait_set_value_(true),
            wait_shutdown_response_(true),
            run_thread_(std::bind(&subscribe_notify_test_one_event_two_eventgroups_client::run, this)) {
    }
    ~subscribe_notify_test_one_event_two_eventgroups_client() {
        run_thread_.join();
    }

    bool init() {
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return false;
        }

        app_->register_state_handler(
                std::bind(
                        &subscribe_notify_test_one_event_two_eventgroups_client::on_state,
                        this, std::placeholders::_1));

        app_->register_message_handler(vsomeip::ANY_SERVICE,
                vsomeip::ANY_INSTANCE, vsomeip::ANY_METHOD,
                std::bind(
                        &subscribe_notify_test_one_event_two_eventgroups_client::on_message,
                        this, std::placeholders::_1));

        app_->register_availability_handler(info_.service_id, info_.instance_id,
                std::bind(
                        &subscribe_notify_test_one_event_two_eventgroups_client::on_availability,
                        this, std::placeholders::_1, std::placeholders::_2,
                        std::placeholders::_3));

        std::set<vsomeip::eventgroup_t> its_groups;
        // the service offers three events in two eventgroups
        // one of the events is in both eventgroups (info_.event_id + 2)
        its_groups.insert(info_.eventgroup_id);
        app_->request_event(info_.service_id, info_.instance_id,
                info_.event_id, its_groups,
                vsomeip::event_type_e::ET_FIELD,
                (use_tcp_ ? vsomeip::reliability_type_e::RT_RELIABLE : vsomeip::reliability_type_e::RT_UNRELIABLE));
        app_->request_event(info_.service_id, info_.instance_id,
                static_cast<vsomeip::event_t>(info_.event_id + 2),
                its_groups, vsomeip::event_type_e::ET_FIELD,
                (use_tcp_ ? vsomeip::reliability_type_e::RT_RELIABLE : vsomeip::reliability_type_e::RT_UNRELIABLE));
        its_groups.erase(info_.eventgroup_id);
        its_groups.insert(static_cast<vsomeip::eventgroup_t>(info_.eventgroup_id +1));
        app_->request_event(info_.service_id, info_.instance_id,
                static_cast<vsomeip::event_t>(info_.event_id+1),
                its_groups, vsomeip::event_type_e::ET_FIELD,
                (use_tcp_ ? vsomeip::reliability_type_e::RT_RELIABLE : vsomeip::reliability_type_e::RT_UNRELIABLE));
        app_->request_event(info_.service_id, info_.instance_id,
                static_cast<vsomeip::event_t>(info_.event_id+2),
                its_groups, vsomeip::event_type_e::ET_FIELD,
                (use_tcp_ ? vsomeip::reliability_type_e::RT_RELIABLE : vsomeip::reliability_type_e::RT_UNRELIABLE));

        return true;
    }

    void start() {
        app_->start();
    }

    void stop() {
        app_->clear_all_handler();
        app_->unsubscribe(info_.service_id, info_.instance_id, info_.eventgroup_id);
        app_->unsubscribe(info_.service_id, info_.instance_id, static_cast<vsomeip::eventgroup_t>(info_.eventgroup_id+1));
        app_->release_event(info_.service_id, info_.instance_id, info_.event_id);
        app_->release_event(info_.service_id, info_.instance_id, static_cast<vsomeip::event_t>(info_.event_id+1));
        app_->release_event(info_.service_id, info_.instance_id, static_cast<vsomeip::event_t>(info_.event_id+2));
        app_->release_service(info_.service_id, info_.instance_id);
        app_->stop();
    }

    void on_state(vsomeip::state_type_e _state) {
        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            app_->request_service(info_.service_id, info_.instance_id);
        }
    }

    void on_availability(vsomeip::service_t _service,
            vsomeip::instance_t _instance,
            bool _is_available) {
        VSOMEIP_DEBUG << "Service ["
                << std::setw(4) << std::setfill('0') << std::hex << _service
                << "." << _instance << "] is "
                << (_is_available ? "available." : "NOT available.");
        if (_service == info_.service_id && _instance == info_.instance_id && _is_available) {
            std::lock_guard<std::mutex> its_lock(availability_mutex_);
            wait_availability_ = false;
            availability_condition_.notify_one();
        }
    }

    void on_message(const std::shared_ptr<vsomeip::message> &_response) {
        std::stringstream its_message;
        its_message << "Received a message ["
                << std::setw(4)    << std::setfill('0') << std::hex
                << _response->get_service() << "."
                << std::setw(4) << std::setfill('0') << std::hex
                << _response->get_instance() << "."
                << std::setw(4) << std::setfill('0') << std::hex
                << _response->get_method() << "] from Client/Session ["
                << std::setw(4) << std::setfill('0') << std::hex
                << _response->get_client() << "/"
                << std::setw(4) << std::setfill('0') << std::hex
                << _response->get_session()
                << "] = ";
        std::shared_ptr<vsomeip::payload> its_payload =
                _response->get_payload();
        its_message << "(" << std::dec << its_payload->get_length() << ") ";
        for (uint32_t i = 0; i < its_payload->get_length(); ++i)
            its_message << std::hex << std::setw(2) << std::setfill('0')
                << (int) its_payload->get_data()[i] << " ";
        VSOMEIP_DEBUG << its_message.str();
        ASSERT_EQ(info_.service_id, _response->get_service());

        if (_response->get_method() == info_.method_id
                || _response->get_method() == subscribe_notify_test::shutdown_method_id) {
            ASSERT_EQ(vsomeip::message_type_e::MT_RESPONSE, _response->get_message_type());
            ASSERT_EQ(vsomeip::return_code_e::E_OK, _response->get_return_code());
            std::lock_guard<std::mutex> its_lock(shutdown_response_mutex_);
            wait_shutdown_response_ = false;
            shutdown_response_condition_.notify_one();
        } else if (_response->get_method() == subscribe_notify_test::set_method_id) {
            std::lock_guard<std::mutex> its_lock(set_value_mutex_);
            wait_set_value_ = false;
            set_value_condition_.notify_one();
        } else if (_response->get_method() >= info_.event_id
                && _response->get_method() <= static_cast<vsomeip::event_t>(info_.event_id + 3)) {
            std::lock_guard<std::mutex> its_lock(events_mutex_);
            received_events_.push_back(_response->get_payload());
            if (received_events_.size() > 4) {
                ADD_FAILURE() << "Received too many events ["
                        << std::hex << _response->get_method()
                        << " (" << std::dec << received_events_.size() << ")";
            }
            number_received_events_[_response->get_method()]++;
            events_condition_.notify_one();
        } else {
            ADD_FAILURE() << "Received unknown method id: " << std::setw(4)
                << std::setfill('0') << std::hex << _response->get_method();
        }

    }

    void set_field_at_service(vsomeip::byte_t _value) {
        std::shared_ptr<vsomeip::runtime> its_runtime = vsomeip::runtime::get();
        std::shared_ptr<vsomeip::message> its_request = its_runtime->create_request(false);
        its_request->set_service(info_.service_id);
        its_request->set_instance(info_.instance_id);
        its_request->set_method(subscribe_notify_test::set_method_id);
        its_request->set_reliable(use_tcp_);
        std::shared_ptr<vsomeip::payload> its_payload = its_runtime->create_payload(&_value, sizeof(_value));
        its_request->set_payload(its_payload);
        app_->send(its_request);
    }

    void call_method_at_service(vsomeip::method_t _method) {
        std::shared_ptr<vsomeip::runtime> its_runtime = vsomeip::runtime::get();
        std::shared_ptr<vsomeip::message> its_request = its_runtime->create_request(false);
        its_request->set_service(info_.service_id);
        its_request->set_instance(info_.instance_id);
        its_request->set_method(_method);
        its_request->set_reliable(use_tcp_);
        app_->send(its_request);
    }

    void wait_on_condition(std::unique_lock<std::mutex>&& _lock, bool *_predicate, std::condition_variable&& _condition, std::uint32_t _timeout) {
        while (*_predicate) {
            if (std::cv_status::timeout == _condition.wait_for(_lock, std::chrono::seconds(_timeout))) {
                ADD_FAILURE() << "Condition variable wasn't notified within time ("
                        << _timeout << "sec)";
            }
        }
        *_predicate = true;
    }

    void subscribe_at_service() {
        // subscribe to both eventgroups
        app_->subscribe(info_.service_id, info_.instance_id, info_.eventgroup_id);
        app_->subscribe(info_.service_id, info_.instance_id, static_cast<vsomeip::eventgroup_t>(info_.eventgroup_id+1));
    }

    void unsubscribe_at_service() {
        app_->unsubscribe(info_.service_id, info_.instance_id, info_.eventgroup_id);
        app_->unsubscribe(info_.service_id, info_.instance_id, static_cast<vsomeip::eventgroup_t>(info_.eventgroup_id+1));
    }

    void wait_for_events(std::unique_lock<std::mutex>&& _lock,
                         std::uint32_t _expected_number_received_events,
                         std::condition_variable&& _condition) {
        std::cv_status its_status(std::cv_status::no_timeout);
        while (received_events_.size() != _expected_number_received_events
                && its_status != std::cv_status::timeout) {
            its_status = _condition.wait_for(_lock, std::chrono::seconds(15));
            if (std::cv_status::timeout == its_status) {
                ADD_FAILURE() << "Didn't receive expected number of events: "
                        << _expected_number_received_events
                        << " within time. Instead received: " << received_events_.size();
            }
        }
        ASSERT_EQ(size_t(_expected_number_received_events), received_events_.size());
    }

    void check_received_events_payload(vsomeip::byte_t _value) {
        for (const auto &p : received_events_) {
            ASSERT_EQ(vsomeip::length_t(1), p->get_length());
            ASSERT_EQ(vsomeip::byte_t(_value), *p->get_data());
        }
        received_events_.clear();
    }

    void check_received_events_number(std::set<std::pair<vsomeip::event_t, std::uint32_t>> _expected) {
        for (const auto &e : _expected) {
            auto event = number_received_events_.find(e.first);
            ASSERT_NE(number_received_events_.end(), event);
            ASSERT_EQ(e.second, event->second);
        }
        number_received_events_.clear();
    }

    void run() {
        std::unique_lock<std::mutex> its_availability_lock(availability_mutex_);
        wait_on_condition(std::move(its_availability_lock), &wait_availability_, std::move(availability_condition_), 300);
        // service is available now

        for (int i = 0; i < 3; i++) {
            // set value
            set_field_at_service(0x1);
            {
                std::unique_lock<std::mutex> its_set_value_lock(set_value_mutex_);
                wait_on_condition(std::move(its_set_value_lock), &wait_set_value_, std::move(set_value_condition_), 30);
            }

            // subscribe
            std::unique_lock<std::mutex> its_events_lock(events_mutex_);
            subscribe_at_service();
            wait_for_events(std::move(its_events_lock), 4, std::move(events_condition_));
            check_received_events_payload(0x1);

            std::set<std::pair<vsomeip::event_t, std::uint32_t>> its_expected;
            its_expected.insert({info_.event_id, 1});
            its_expected.insert({static_cast<vsomeip::event_t>(info_.event_id+1), 1});
            // Initial event for the event which is member of both eventgroups has to be sent twice
            its_expected.insert({static_cast<vsomeip::event_t>(info_.event_id+2), 2});

            check_received_events_number(its_expected);
            its_expected.clear();
            // set value again
            set_field_at_service(0x2);
            {
                std::unique_lock<std::mutex> its_set_value_lock(set_value_mutex_);
                wait_on_condition(std::move(its_set_value_lock), &wait_set_value_, std::move(set_value_condition_), 30);
            }

            wait_for_events(std::move(its_events_lock), 3, std::move(events_condition_));
            check_received_events_payload(0x2);
            its_expected.insert({info_.event_id, 1});
            its_expected.insert({static_cast<vsomeip::event_t>(info_.event_id+1), 1});
            its_expected.insert({static_cast<vsomeip::event_t>(info_.event_id+2), 1});

            check_received_events_number(its_expected);
            its_expected.clear();

            // set value again
            set_field_at_service(0x3);
            {
                std::unique_lock<std::mutex> its_set_value_lock(set_value_mutex_);
                wait_on_condition(std::move(its_set_value_lock), &wait_set_value_, std::move(set_value_condition_), 30);
            }
            wait_for_events(std::move(its_events_lock), 3, std::move(events_condition_));
            check_received_events_payload(0x3);
            its_expected.insert({info_.event_id, 1});
            its_expected.insert({static_cast<vsomeip::event_t>(info_.event_id+1), 1});
            its_expected.insert({static_cast<vsomeip::event_t>(info_.event_id+2), 1});
            check_received_events_number(its_expected);

            unsubscribe_at_service();
            // sleep some time to ensure the unsubscription was processed by the
            // remote routing_manager before setting the field again in the next
            // loop.
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
        std::unique_lock<std::mutex> its_shutdown_lock(shutdown_response_mutex_);
        call_method_at_service(subscribe_notify_test::shutdown_method_id);
        wait_on_condition(std::move(its_shutdown_lock), &wait_shutdown_response_, std::move(shutdown_response_condition_), 30);
        stop();
    }

private:
    std::shared_ptr<vsomeip::application> app_;
    struct subscribe_notify_test::service_info info_;
    bool use_tcp_;

    bool wait_availability_;
    std::mutex availability_mutex_;
    std::condition_variable availability_condition_;

    bool wait_set_value_;
    std::mutex set_value_mutex_;
    std::condition_variable set_value_condition_;

    bool wait_shutdown_response_;
    std::mutex shutdown_response_mutex_;
    std::condition_variable shutdown_response_condition_;

    std::mutex events_mutex_;
    std::condition_variable events_condition_;

    std::vector<std::shared_ptr<vsomeip::payload>> received_events_;
    std::map<vsomeip::event_t, std::uint32_t> number_received_events_;
    std::thread run_thread_;
};

#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
    subscribe_notify_test_one_event_two_eventgroups_client *its_client_ptr(nullptr);
    void handle_signal(int _signal) {
        if (its_client_ptr != nullptr &&
                (_signal == SIGINT || _signal == SIGTERM))
            its_client_ptr->stop();
    }
#endif

static bool use_tcp;

TEST(someip_subscribe_notify_test_one_event_two_eventgroups, subscribe_to_service)
{
    subscribe_notify_test_one_event_two_eventgroups_client its_client(
            subscribe_notify_test::service_info_subscriber_based_notification, use_tcp);
#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
    its_client_ptr = &its_client;
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
#endif
    if (its_client.init()) {
        its_client.start();
    }
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    if(argc < 2) {
        std::cerr << "Please specify a offer type of the service, like: " << argv[0] << " UDP" << std::endl;
        std::cerr << "Valid offer types include:" << std::endl;
        std::cerr << "[UDP, TCP]" << std::endl;
        return 1;
    }

    if(std::string("TCP") == std::string(argv[1])) {
        use_tcp = true;
    } else if(std::string("UDP") == std::string(argv[1])) {
        use_tcp = false;
    } else {
        std::cerr << "Wrong subscription type passed, exiting" << std::endl;
        std::cerr << "Valid subscription types include:" << std::endl;
        std::cerr << "[UDP, TCP]" << std::endl;
        return 1;
    }

    return RUN_ALL_TESTS();
}
#endif
