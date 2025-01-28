// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <chrono>
#include <iomanip>

#include <vsomeip/internal/logger.hpp>

#include "debounce_filter_test_client.hpp"

static std::vector<std::vector<std::shared_ptr<vsomeip::payload>>> payloads__;

debounce_test_client::debounce_test_client(int64_t _interval) :
    interval(_interval), index_(0), is_available_(false),
    runner_(std::bind(&debounce_test_client::run, this)),
    app_(vsomeip::runtime::get()->create_application("debounce_test_client")), sum_time(0) { }

bool debounce_test_client::init() {
    dBFilter.interval_ = interval;

    bool its_result = app_->init();
    if (its_result) {
        app_->register_availability_handler(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE,
                                            std::bind(&debounce_test_client::on_availability, this,
                                                      std::placeholders::_1, std::placeholders::_2,
                                                      std::placeholders::_3),
                                            DEBOUNCE_MAJOR, DEBOUNCE_MINOR);
        app_->register_message_handler(
                DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, vsomeip::ANY_EVENT,
                std::bind(&debounce_test_client::on_message, this, std::placeholders::_1));
        app_->request_event(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT,
                            {DEBOUNCE_EVENTGROUP}, vsomeip::event_type_e::ET_FIELD,
                            vsomeip::reliability_type_e::RT_UNRELIABLE);
        app_->request_service(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_MAJOR, DEBOUNCE_MINOR);
        app_->subscribe_with_debounce(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENTGROUP,
                                      DEBOUNCE_MAJOR, DEBOUNCE_EVENT, dBFilter);
    }
    return its_result;
}

void debounce_test_client::start() {
    VSOMEIP_INFO << "Starting Client...";
    app_->start();
}

void debounce_test_client::stop() {
    VSOMEIP_INFO << "Stopping Client...";
    app_->stop();
}

void debounce_test_client::run() {
    {
        std::unique_lock<std::mutex> its_lock(run_mutex_);
        while (!is_available_) {
            auto its_status = run_condition_.wait_for(its_lock, std::chrono::milliseconds(15000));
            EXPECT_EQ(its_status, std::cv_status::no_timeout);
            if (its_status == std::cv_status::timeout) {
                VSOMEIP_ERROR << __func__
                              << ": Debounce service did not become available after 15s.";
                stop();
                return;
            }
        }
    }

    VSOMEIP_INFO << __func__ << ": Running test.";
    run_test();

    unsubscribe_all();

    VSOMEIP_INFO << __func__ << ": Stopping the service.";
    stop_service();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    stop();
}

void debounce_test_client::wait() {
    if (runner_.joinable())
        runner_.join();
}

void debounce_test_client::on_availability(vsomeip::service_t _service,
                                           vsomeip::instance_t _instance, bool _is_available) {
    if (_service == DEBOUNCE_SERVICE && _instance == DEBOUNCE_INSTANCE) {

        if (_is_available) {
            VSOMEIP_INFO << __func__ << ": Debounce service becomes available.";
            {
                std::lock_guard<std::mutex> its_lock(run_mutex_);
                is_available_ = true;
            }
            run_condition_.notify_one();
        } else {
            VSOMEIP_INFO << __func__ << ": Debounce service becomes unavailable.";

            std::lock_guard<std::mutex> its_lock(run_mutex_);
            is_available_ = false;
        }
    }
}

void debounce_test_client::on_message(const std::shared_ptr<vsomeip::message>& _message) {
    if (!nb_msgs_rcvd) {
        time_start = std::chrono::high_resolution_clock::now();
        time_last = time_start;
    } else {
        time_last = std::chrono::high_resolution_clock::now();
    }

    std::stringstream s;
    s << "RECV: ";
    for (uint32_t i = 0; i < _message->get_payload()->get_length(); i++) {
        s << std::hex << std::setw(3) << std::setfill('0')
          << static_cast<int>(_message->get_payload()->get_data()[i]) << " ";
    }

    if (DEBOUNCE_SERVICE == _message->get_service() && DEBOUNCE_EVENT == _message->get_method()) {
        nb_msgs_rcvd++;
        s << "\t- Message: " << std::dec << std::setw(2) << nb_msgs_rcvd;

        if (nb_msgs_rcvd >= 2) {
            std::chrono::duration elapsed_time_ms = (time_last - time_start);
            sum_time += std::chrono::duration_cast<std::chrono::milliseconds>(elapsed_time_ms);
            s << " Average interval is " << get_avgtime().count() << " ms";
        }
        VSOMEIP_DEBUG << s.str();
        s.clear();
    }
    time_start = time_last;
}

void debounce_test_client::run_test() {
    // Trigger the test
    auto its_runtime = vsomeip::runtime::get();
    auto its_payload = its_runtime->create_payload();
    auto its_message = its_runtime->create_request(false);
    its_message->set_service(DEBOUNCE_SERVICE);
    its_message->set_instance(DEBOUNCE_INSTANCE);
    its_message->set_method(DEBOUNCE_START_METHOD);
    its_message->set_interface_version(DEBOUNCE_MAJOR);
    its_message->set_message_type(vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
    its_message->set_payload(its_payload);
    app_->send(its_message);

    std::this_thread::sleep_for(std::chrono::seconds(15));
}

void debounce_test_client::unsubscribe_all() {
    app_->unsubscribe(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENTGROUP);
}

void debounce_test_client::stop_service() {
    auto its_runtime = vsomeip::runtime::get();
    auto its_payload = its_runtime->create_payload();
    auto its_message = its_runtime->create_request(false);
    its_message->set_service(DEBOUNCE_SERVICE);
    its_message->set_instance(DEBOUNCE_INSTANCE);
    its_message->set_method(DEBOUNCE_STOP_METHOD);
    its_message->set_interface_version(DEBOUNCE_MAJOR);
    its_message->set_message_type(vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
    its_message->set_payload(its_payload);
    app_->send(its_message);
}

int64_t debounce_test_client::getNbMsgsRcvd() {
    return nb_msgs_rcvd;
}

std::chrono::milliseconds debounce_test_client::get_avgtime() {
    return (sum_time / (getNbMsgsRcvd() - 1));
}

TEST(debounce_test, normal_interval) {
    debounce_test_client its_client(DEBOUNCE_INTERVAL_1);
    ASSERT_TRUE(its_client.init());
    VSOMEIP_INFO << "Debounce client successfully initialized!";
    its_client.start();
    its_client.wait();

    // Average Interval should be between 95ms and 105ms
    EXPECT_GE(its_client.get_avgtime().count(), (double)DEBOUNCE_INTERVAL_1 - 5);
    EXPECT_LE(its_client.get_avgtime().count(), (double)DEBOUNCE_INTERVAL_1 + 5);
}

TEST(debounce_test, large_interval) {
    debounce_test_client its_client(DEBOUNCE_INTERVAL_2);
    ASSERT_TRUE(its_client.init());
    VSOMEIP_INFO << "Debounce client successfully initialized!";
    its_client.start();
    its_client.wait();

    // Average Interval should be between 995ms and 1005ms
    EXPECT_GE(its_client.get_avgtime().count(), (double)DEBOUNCE_INTERVAL_2 - 5);
    EXPECT_LE(its_client.get_avgtime().count(), (double)DEBOUNCE_INTERVAL_2 + 5);
}

TEST(debounce_test, disable) {
    debounce_test_client its_client(DEBOUNCE_INTERVAL_3);
    ASSERT_TRUE(its_client.init());
    VSOMEIP_INFO << "Debounce Client successfully initialized!";
    its_client.start();
    its_client.wait();

    // With a debounce interval disabled (-1), the client is expected to not receive any message
    EXPECT_EQ(its_client.getNbMsgsRcvd(), 0);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
