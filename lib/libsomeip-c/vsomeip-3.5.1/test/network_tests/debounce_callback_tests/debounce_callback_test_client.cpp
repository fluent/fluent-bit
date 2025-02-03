// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <chrono>
#include <iomanip>

#include <vsomeip/internal/logger.hpp>

#include "debounce_callback_test_client.hpp"

static std::vector<std::shared_ptr<vsomeip::payload>> payloads__;

debounce_test_client::debounce_test_client(int64_t _interval) :
    interval(_interval), index_(0), is_available_(false),
    runner_(std::bind(&debounce_test_client::run, this)),
    app_(vsomeip::runtime::get()->create_application("debounce_timeout_test_client")) { }

bool debounce_test_client::init() {

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
        app_->request_event(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2,
                            {DEBOUNCE_EVENTGROUP}, vsomeip::event_type_e::ET_FIELD,
                            vsomeip::reliability_type_e::RT_UNRELIABLE);
        app_->request_service(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_MAJOR, DEBOUNCE_MINOR);
        app_->subscribe(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENTGROUP, DEBOUNCE_MAJOR,
                        DEBOUNCE_EVENT);
        app_->subscribe(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENTGROUP, DEBOUNCE_MAJOR,
                        DEBOUNCE_EVENT_2);
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
            VSOMEIP_ERROR << __func__ << ": Debounce service becomes available.";
            {
                std::lock_guard<std::mutex> its_lock(run_mutex_);
                is_available_ = true;
            }
            run_condition_.notify_one();
        } else {
            VSOMEIP_ERROR << __func__ << ": Debounce service becomes unavailable.";

            std::lock_guard<std::mutex> its_lock(run_mutex_);
            is_available_ = false;
        }
    }
}

void debounce_test_client::on_message(const std::shared_ptr<vsomeip::message>& _message) {

    std::stringstream s;
    s << "RECV: ";
    for (uint32_t i = 0; i < _message->get_payload()->get_length(); i++) {
        s << std::hex << std::setw(2) << std::setfill('0')
          << static_cast<int>(_message->get_payload()->get_data()[i]) << ' ';
    }
    VSOMEIP_DEBUG << s.str();

    // Check if message received is equal to the one it was expecting
    if (DEBOUNCE_SERVICE == _message->get_service()
        && (DEBOUNCE_EVENT == _message->get_method()
            || DEBOUNCE_EVENT_2 == _message->get_method())) {
        bool is_equal = compare_payload(_message->get_payload(), index_++);
        EXPECT_EQ(is_equal, true);
    }
}

bool debounce_test_client::compare_payload(const std::shared_ptr<vsomeip::payload>& _payload,
                                           std::size_t _index) const {

    auto its_expected_payload = payloads__[_index];
    return (*_payload == *its_expected_payload);
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

    std::this_thread::sleep_for(std::chrono::seconds(23));
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

size_t debounce_test_client::getIndex() {
    return index_;
}

TEST(debounce_timeout_test, callback) {
    // Interval time of 2 seconds
    debounce_test_client its_client(2000);
    ASSERT_TRUE(its_client.init());
    VSOMEIP_ERROR << "Debounce Client successfully initialized!";
    its_client.start();
    its_client.wait();

    // Check it got all messages
    EXPECT_EQ(its_client.getIndex(), payloads__.size());
}
int main(int argc, char** argv) {

    std::shared_ptr<vsomeip::payload> its_payload;

    its_payload = vsomeip::runtime::get()->create_payload();
    its_payload->set_data({0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
    payloads__.push_back(its_payload);

    its_payload = vsomeip::runtime::get()->create_payload();
    its_payload->set_data({0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09});
    payloads__.push_back(its_payload);

    its_payload = vsomeip::runtime::get()->create_payload();
    its_payload->set_data({0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
    payloads__.push_back(its_payload);

    its_payload = vsomeip::runtime::get()->create_payload();
    its_payload->set_data({0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09});
    payloads__.push_back(its_payload);

    its_payload = vsomeip::runtime::get()->create_payload();
    its_payload->set_data({0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
    payloads__.push_back(its_payload);

    its_payload = vsomeip::runtime::get()->create_payload();
    its_payload->set_data({0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09});
    payloads__.push_back(its_payload);

    its_payload = vsomeip::runtime::get()->create_payload();
    its_payload->set_data({0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
    payloads__.push_back(its_payload);

    its_payload = vsomeip::runtime::get()->create_payload();
    its_payload->set_data({0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
    payloads__.push_back(its_payload);

    its_payload = vsomeip::runtime::get()->create_payload();
    its_payload->set_data({0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09});
    payloads__.push_back(its_payload);

    its_payload = vsomeip::runtime::get()->create_payload();
    its_payload->set_data({0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09});
    payloads__.push_back(its_payload);

    its_payload = vsomeip::runtime::get()->create_payload();
    its_payload->set_data({0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00});
    payloads__.push_back(its_payload);

    its_payload = vsomeip::runtime::get()->create_payload();
    its_payload->set_data({0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00});
    payloads__.push_back(its_payload);

    its_payload = vsomeip::runtime::get()->create_payload();
    its_payload->set_data({0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0D});
    payloads__.push_back(its_payload);

    its_payload = vsomeip::runtime::get()->create_payload();
    its_payload->set_data({0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0D});
    payloads__.push_back(its_payload);

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
