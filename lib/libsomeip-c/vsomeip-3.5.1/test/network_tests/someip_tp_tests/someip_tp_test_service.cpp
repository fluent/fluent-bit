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
#include <future>
#include <cstring>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>
#include "../../implementation/endpoints/include/tp.hpp"

#include "someip_tp_test_globals.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class someip_tp_test_service : public vsomeip_utilities::base_logger {
public:
    someip_tp_test_service(struct someip_tp_test::service_info _service_info, someip_tp_test::test_mode_e _testmode) :
            vsomeip_utilities::base_logger("STTS", "SOMEIP TP TEST SERVICE"),
            service_info_(_service_info),
            testmode_(_testmode),
            app_(vsomeip::runtime::get()->create_application("someip_tp_test_service")),
            wait_until_registered_(true),
            wait_until_shutdown_method_called_(true),
            wait_for_slave_subscription_(true),
            number_notifications_of_slave_(0x0),
            wait_for_slave_service_available_(true),
            wait_for_two_responses_of_slave_(true),
            number_responses_of_slave_(0),
            wait_for_two_requests_of_slave_(true),
            number_requests_from_slave_(0),
            wait_for_two_notifications_of_slave_(true) {
    }

    void start() {
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }
        app_->register_state_handler(
                std::bind(&someip_tp_test_service::on_state, this,
                        std::placeholders::_1));

        // offer field
        std::set<vsomeip::eventgroup_t> its_eventgroups;
        its_eventgroups.insert(service_info_.eventgroup_id);
        app_->offer_event(service_info_.service_id, service_info_.instance_id,
                service_info_.event_id, its_eventgroups,
                vsomeip::event_type_e::ET_EVENT, std::chrono::milliseconds::zero(),
                false, true, nullptr, vsomeip::reliability_type_e::RT_UNRELIABLE);

        app_->register_message_handler(vsomeip::ANY_SERVICE,
                vsomeip::ANY_INSTANCE, service_info_.shutdown_method_id,
                std::bind(&someip_tp_test_service::on_shutdown_method_called, this,
                        std::placeholders::_1));

        app_->register_message_handler(vsomeip::ANY_SERVICE,
                vsomeip::ANY_INSTANCE, service_info_.notify_method_id,
                std::bind(&someip_tp_test_service::on_notify_method_called, this,
                        std::placeholders::_1));
        app_->register_message_handler(vsomeip::ANY_SERVICE,
                vsomeip::ANY_INSTANCE, service_info_.method_id,
                std::bind(&someip_tp_test_service::on_message, this,
                        std::placeholders::_1));

        app_->register_async_subscription_handler(service_info_.service_id,
                0x1, service_info_.eventgroup_id,
                std::bind(&someip_tp_test_service::subscription_handler_async,
                          this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3,
                          std::placeholders::_4, std::placeholders::_5));

        // request remote service
        app_->request_service(someip_tp_test::service_slave.service_id,
                someip_tp_test::service_slave.instance_id);
        its_eventgroups.clear();
        its_eventgroups.insert(someip_tp_test::service_slave.eventgroup_id);
        app_->request_event(someip_tp_test::service_slave.service_id,
                someip_tp_test::service_slave.instance_id,
                someip_tp_test::service_slave.event_id, its_eventgroups,
                vsomeip::event_type_e::ET_EVENT,
                vsomeip::reliability_type_e::RT_UNRELIABLE);
        app_->register_message_handler(someip_tp_test::service_slave.service_id,
                someip_tp_test::service_slave.instance_id,
                someip_tp_test::service_slave.event_id,
                std::bind(&someip_tp_test_service::on_notification, this,
                        std::placeholders::_1));
        app_->subscribe(someip_tp_test::service_slave.service_id,
                someip_tp_test::service_slave.instance_id,
                someip_tp_test::service_slave.eventgroup_id, 0x0,
                someip_tp_test::service_slave.event_id);
        app_->register_availability_handler(someip_tp_test::service_slave.service_id,
                someip_tp_test::service_slave.instance_id,
                std::bind(&someip_tp_test_service::on_availability, this,
                          std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
        app_->register_message_handler(
                someip_tp_test::service_slave.service_id,
                someip_tp_test::service_slave.instance_id,
                someip_tp_test::service_slave.method_id,
                std::bind(&someip_tp_test_service::on_response_from_slave, this,
                        std::placeholders::_1));

        start_thread_ = std::make_shared<std::thread>([this]() {
            app_->start();
        });
    }

    ~someip_tp_test_service() {}

    void offer() {
        app_->offer_service(service_info_.service_id, 0x1);
    }

    void stop() {
        app_->stop_offer_service(service_info_.service_id, service_info_.instance_id);
        app_->clear_all_handler();
        app_->stop();

        start_thread_->join();
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

    void on_availability(vsomeip::service_t _service, vsomeip::instance_t _instance, bool _available) {
        if (_service == someip_tp_test::service_slave.service_id &&
                _instance == someip_tp_test::service_slave.instance_id &&
                _available) {
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_for_slave_service_available_ = false;
            condition_.notify_one();
            VSOMEIP_INFO << "Service available Service/Instance ["
                    << std::setw(4) << std::setfill('0') << std::hex << _service << "/"
                    << std::setw(4) << std::setfill('0') << std::hex << _instance << "]";
        }
    }

    void on_message(const std::shared_ptr<vsomeip::message>& _message) {
        VSOMEIP_INFO << "Received a message with Client/Session ["
                << std::setw(4) << std::setfill('0') << std::hex << _message->get_client() << "/"
                << std::setw(4) << std::setfill('0') << std::hex << _message->get_session()
                << "] size: " << std::dec << _message->get_payload()->get_length();
        auto response = vsomeip::runtime::get()->create_response(_message);
        auto payload = vsomeip::runtime::get()->create_payload(_message->get_payload()->get_data(), _message->get_payload()->get_length());
        response->set_payload(payload);
        app_->send(response);
        if (++number_requests_from_slave_ == 2) {
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_for_two_requests_of_slave_ = false;
            condition_.notify_one();
        }
    }

    void on_notification(const std::shared_ptr<vsomeip::message>& _message) {
        VSOMEIP_INFO << "Received a notification with Client/Session ["
                << std::setw(4) << std::setfill('0') << std::hex << _message->get_client() << "/"
                << std::setw(4) << std::setfill('0') << std::hex << _message->get_session()
                << "] size: " << std::dec << _message->get_payload()->get_length();
        EXPECT_EQ(someip_tp_test::service_slave.service_id, _message->get_service());
        EXPECT_EQ(someip_tp_test::service_slave.event_id, _message->get_method());
        std::vector<vsomeip::byte_t> its_cmp_data =
                generate_payload(someip_tp_test::number_of_fragments,
                        (testmode_ == someip_tp_test::test_mode_e::OVERLAP
                            || testmode_ == someip_tp_test::test_mode_e::OVERLAP_FRONT_BACK) ?
                                someip_tp_test::max_segment_size - 160 :
                                someip_tp_test::max_segment_size);

        std::vector<vsomeip::byte_t> its_rcv_data(_message->get_payload()->get_data(),
                _message->get_payload()->get_data() + _message->get_payload()->get_length());
        EXPECT_EQ(its_cmp_data.size(), its_rcv_data.size());
        if (testmode_ == someip_tp_test::test_mode_e::OVERLAP) {
            if (number_notifications_of_slave_ == 0) { //ASCENDING with 2nd segment too big
                for (std::uint32_t i = 0; i < 16; i++) {
                    its_cmp_data[2 * (someip_tp_test::max_segment_size - 160) + i] = 0xff;
                }
            } else if (number_notifications_of_slave_ == 1) {
                // DESCENDING with 2nd last segment too big
                // no action as successive 4 byte at end of message would
                // overwrite the beginning of the last segment which was received first
            }
        }
        EXPECT_EQ(its_cmp_data, its_rcv_data);
        EXPECT_EQ(0, std::memcmp(static_cast<void*>(&its_cmp_data[0]),
                                 static_cast<void*>(&its_rcv_data[0]),
                                 its_cmp_data.size()));
        if (++number_notifications_of_slave_ == 2) {
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_for_two_notifications_of_slave_ = false;
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

    void on_notify_method_called(const std::shared_ptr<vsomeip::message> &_message) {
        (void)_message;
        std::vector<vsomeip::byte_t> its_data = generate_payload(someip_tp_test::number_of_fragments,
                (testmode_ == someip_tp_test::test_mode_e::OVERLAP) ?
                                                someip_tp_test::max_segment_size - 160 :
                                                someip_tp_test::max_segment_size);
        std::shared_ptr<vsomeip::payload> its_payload = vsomeip::runtime::get()->create_payload();
        its_payload->set_data(its_data);
        app_->notify(service_info_.service_id, service_info_.instance_id,
                service_info_.event_id, its_payload);
        VSOMEIP_INFO << __func__ << " send event";
        notify_method_called_.set_value(true);
    }

    void send_fragmented_request_to_slave() {
        auto its_req = vsomeip::runtime::get()->create_request();
        its_req->set_service(someip_tp_test::service_slave.service_id);
        its_req->set_instance(someip_tp_test::service_slave.instance_id);
        its_req->set_method(someip_tp_test::service_slave.method_id);
        std::vector<vsomeip::byte_t> its_data = generate_payload(someip_tp_test::number_of_fragments,
                (testmode_ == someip_tp_test::test_mode_e::OVERLAP
                        || testmode_ == someip_tp_test::test_mode_e::OVERLAP_FRONT_BACK) ?
                                                someip_tp_test::max_segment_size - 160 :
                                                someip_tp_test::max_segment_size);
        auto its_payload = vsomeip::runtime::get()->create_payload();
        its_payload->set_data(its_data);
        its_req->set_payload(its_payload);
        request_send_to_slave_ = its_req;
        app_->send(its_req);
    }

    void on_response_from_slave(const std::shared_ptr<vsomeip::message> &_message) {
        VSOMEIP_INFO << "Received a response from the slave with Client/Session ["
                << std::setw(4) << std::setfill('0') << std::hex << _message->get_client() << "/"
                << std::setw(4) << std::setfill('0') << std::hex << _message->get_session()
                << "] size: " << std::dec << _message->get_payload()->get_length();
        EXPECT_EQ(someip_tp_test::service_slave.service_id, _message->get_service());
        EXPECT_EQ(someip_tp_test::service_slave.instance_id, _message->get_instance());
        EXPECT_EQ(someip_tp_test::service_slave.method_id, _message->get_method());
        std::vector<vsomeip::byte_t> its_resp_payload(_message->get_payload()->get_data(),
                _message->get_payload()->get_data() + _message->get_payload()->get_length());
        std::vector<vsomeip::byte_t> its_req_payload(request_send_to_slave_->get_payload()->get_data(),
                request_send_to_slave_->get_payload()->get_data() + request_send_to_slave_->get_payload()->get_length());
        if (testmode_ == someip_tp_test::test_mode_e::OVERLAP) {
            if (number_responses_of_slave_ == 0) { //ASCENDING with 2nd segment too big
                for (std::uint32_t i = 0; i < 16; i++) {
                    its_req_payload[2 * (someip_tp_test::max_segment_size - 160) + i] = 0xff;
                }
            } else if (number_responses_of_slave_ == 1) {
                // DESCENDING with 2nd last segment too big
                // no action as successive 4 byte at end of message would
                // overwrite the beginning of the last segment which was received first
            }
        }

        EXPECT_EQ(its_req_payload.size(), its_resp_payload.size());
        EXPECT_EQ(its_req_payload, its_resp_payload);
        EXPECT_EQ(0, std::memcmp(static_cast<void*>(&its_req_payload[0]),
                                 static_cast<void*>(&its_resp_payload[0]),
                                 its_req_payload.size()));

        if (++number_responses_of_slave_ < 2) {
            send_fragmented_request_to_slave();
        } else {
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_for_two_responses_of_slave_ = false;
            condition_.notify_one();
        }
    }

    std::vector<vsomeip::byte_t> generate_payload(std::uint32_t _number_of_fragments,
            std::uint32_t _segment_size) {
        std::vector<vsomeip::byte_t> its_data;
        for (std::uint32_t i = 0; i < _number_of_fragments; i++) {
            its_data.resize((i * _segment_size) + _segment_size,
                    static_cast<std::uint8_t>(i));
        }
        return its_data;
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

        while (wait_for_slave_service_available_) {
            condition_.wait(its_lock);
        }
        send_fragmented_request_to_slave();

        while (wait_for_two_responses_of_slave_) {
            condition_.wait(its_lock);
        }
        EXPECT_EQ(2u, number_responses_of_slave_);

        while (wait_for_two_requests_of_slave_) {
            condition_.wait(its_lock);
        }
        EXPECT_EQ(2u, number_requests_from_slave_);

        while (wait_for_two_notifications_of_slave_) {
            condition_.wait(its_lock);
        }
        EXPECT_EQ(2u, number_notifications_of_slave_);

        while (wait_for_slave_subscription_) {
            condition_.wait(its_lock);
        }
        // slave subscribed --> sent a notification
        on_notify_method_called(vsomeip::runtime::get()->create_message());

        while (wait_until_shutdown_method_called_) {
            condition_.wait(its_lock);
        }
    }

    void subscription_handler_async(vsomeip::client_t _client, std::uint32_t _uid, std::uint32_t _gid,
                                    bool _subscribed, const std::function<void(const bool)>& _cbk) {
        (void)_uid;
        (void)_gid;
        VSOMEIP_WARNING << __func__ << " " << std::hex << _client << " subscribed." << _subscribed;
        static int was_called = 0;
        was_called++;
        EXPECT_EQ(1, was_called);
        EXPECT_TRUE(_subscribed);
        _cbk(true);
        std::lock_guard<std::mutex> its_lock(mutex_);
        wait_for_slave_subscription_ = false;
        condition_.notify_one();
    }


private:
    struct someip_tp_test::service_info service_info_;
    someip_tp_test::test_mode_e testmode_;
    std::shared_ptr<vsomeip::application> app_;

    bool wait_until_registered_;
    bool wait_until_shutdown_method_called_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::atomic<bool> wait_for_slave_subscription_;
    std::atomic<std::uint32_t> number_notifications_of_slave_;
    std::promise<bool> notify_method_called_;
    bool wait_for_slave_service_available_;
    bool wait_for_two_responses_of_slave_;
    std::uint32_t number_responses_of_slave_;
    bool wait_for_two_requests_of_slave_;
    std::uint32_t number_requests_from_slave_;
    bool wait_for_two_notifications_of_slave_;
    std::shared_ptr<vsomeip::message> request_send_to_slave_;
    std::shared_ptr<std::thread> start_thread_;
};

someip_tp_test::test_mode_e its_testmode(someip_tp_test::test_mode_e::IN_SEQUENCE);

TEST(someip_someip_tp_test, echo_requests)
{
    someip_tp_test_service its_sample(someip_tp_test::service, its_testmode);
    its_sample.start();
    its_sample.run();
    its_sample.stop();
}


#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    if (argc < 2) {
        std::cerr << "Please pass a test mode to this binary like: "
                << argv[0] << " IN_SEQUENCE" << std::endl;
        std::cerr << "Testmodes are [ IN_SEQUENCE, MIXED, INCOMPLETE, DUPLICATE, OVERLAP, OVERLAP_FRONT_BACK ]" << std::endl;
        exit(1);
    }

    std::string its_pased_testmode = argv[1];
    if (its_pased_testmode == std::string("IN_SEQUENCE")) {
        its_testmode = someip_tp_test::test_mode_e::IN_SEQUENCE;
    } else if (its_pased_testmode == std::string("MIXED")) {
        its_testmode = someip_tp_test::test_mode_e::MIXED;
    } else if (its_pased_testmode == std::string("INCOMPLETE")) {
        its_testmode = someip_tp_test::test_mode_e::INCOMPLETE;
    } else if (its_pased_testmode == std::string("DUPLICATE")) {
        its_testmode = someip_tp_test::test_mode_e::DUPLICATE;
    } else if (its_pased_testmode == std::string("OVERLAP")) {
        its_testmode = someip_tp_test::test_mode_e::OVERLAP;
    } else if (its_pased_testmode == std::string("OVERLAP_FRONT_BACK")) {
        its_testmode = someip_tp_test::test_mode_e::OVERLAP_FRONT_BACK;
    }

    return RUN_ALL_TESTS();
}
#endif
