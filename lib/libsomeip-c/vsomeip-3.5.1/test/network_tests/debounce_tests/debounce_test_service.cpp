// Copyright (C) 2020 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/internal/logger.hpp>

#include "debounce_test_service.hpp"

debounce_test_service::debounce_test_service(debounce_test_id_e _test_id) :
    test_id_(_test_id), is_running_(true), runner_(std::bind(&debounce_test_service::run, this)),
    app_(vsomeip::runtime::get()->create_application("debounce_test_service")) { }

bool debounce_test_service::init() {

    bool is_initialized = app_->init();
    if (is_initialized) {
        app_->register_message_handler(
                DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_START_METHOD,
                std::bind(&debounce_test_service::on_start, this, std::placeholders::_1));
        app_->register_message_handler(
                DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_STOP_METHOD,
                std::bind(&debounce_test_service::on_stop, this, std::placeholders::_1));
        app_->offer_event(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT,
                          {DEBOUNCE_EVENTGROUP}, vsomeip::event_type_e::ET_FIELD,
                          std::chrono::milliseconds::zero(), false, true, nullptr,
                          vsomeip::reliability_type_e::RT_UNRELIABLE);
        app_->offer_event(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2,
                          {DEBOUNCE_EVENTGROUP}, vsomeip::event_type_e::ET_FIELD,
                          std::chrono::milliseconds::zero(), false, true, nullptr,
                          vsomeip::reliability_type_e::RT_UNRELIABLE);
        app_->offer_event(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_4,
                          {DEBOUNCE_EVENTGROUP}, vsomeip::event_type_e::ET_FIELD,
                          std::chrono::milliseconds::zero(), false, true, nullptr,
                          vsomeip::reliability_type_e::RT_UNRELIABLE);
        app_->offer_service(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_MAJOR, DEBOUNCE_MINOR);
    }
    return is_initialized;
}

void debounce_test_service::start() {

    VSOMEIP_INFO << "Starting Service...";
    app_->start();
}

void debounce_test_service::stop() {

    VSOMEIP_INFO << "Stopping Service...";
    app_->stop();
}

void debounce_test_service::run() {

    {
        std::unique_lock<std::mutex> its_lock(run_mutex_);
        auto its_result = run_condition_.wait_for(its_lock, std::chrono::milliseconds(5000));
        if (its_result == std::cv_status::timeout)
            return;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    start_test();
}

void debounce_test_service::wait() {

    if (runner_.joinable())
        runner_.join();
}

void debounce_test_service::on_start(const std::shared_ptr<vsomeip::message>& _message) {

    (void)_message;

    VSOMEIP_INFO << __func__ << ": Starting test " << std::dec << test_id_;
    run_condition_.notify_one();
}

void debounce_test_service::on_stop(const std::shared_ptr<vsomeip::message>& _message) {

    (void)_message;

    VSOMEIP_INFO << __func__ << ": Received a STOP command.";
    is_running_ = false;
    stop();
}

void debounce_test_service::start_test() {

    if (test_id_ == debounce_test_id_e::DTI_FLAT) {
        auto its_payload = vsomeip::runtime::get()->create_payload();

        its_payload->set_data({0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT, its_payload);

        its_payload->set_data({0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT, its_payload);

        its_payload->set_data({0x02, 0x02, 0x03, 0x04, 0x04, 0x06, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT, its_payload);

        its_payload->set_data({0x03, 0x02, 0x03, 0x04, 0x04, 0x07, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT, its_payload);

        its_payload->set_data({0x04, 0x02, 0x03, 0x04, 0x03, 0x06, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT, its_payload);

        its_payload->set_data({0x05, 0x02, 0x03, 0x04, 0x03, 0x07, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT, its_payload);

        its_payload->set_data({0x06, 0x02, 0x03, 0x04, 0x02, 0x06, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT, its_payload);

        its_payload->set_data({0x07, 0x02, 0x03, 0x04, 0x02, 0x07, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT, its_payload);

        its_payload->set_data({0x08, 0x02, 0x03, 0x04, 0x01, 0x06, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT, its_payload);

        its_payload->set_data({0x09, 0x02, 0x03, 0x04, 0x01, 0x07, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT, its_payload);
    }

    if (test_id_ == debounce_test_id_e::DTI_INCREASE) {
        auto its_payload = vsomeip::runtime::get()->create_payload();

        its_payload->set_data({0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data({0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x07, 0x08});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data({0x02, 0x02, 0x03, 0x04, 0x04, 0x06, 0x07, 0x08});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data({0x03, 0x02, 0x03, 0x04, 0x04, 0x07, 0x07, 0x08, 0x09});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data({0x04, 0x02, 0x03, 0x04, 0x03, 0x06, 0x07, 0x08, 0x09});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data({0x05, 0x02, 0x03, 0x04, 0x03, 0x07, 0x07, 0x08, 0x09, 0x0A});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data({0x06, 0x02, 0x03, 0x04, 0x02, 0x06, 0x07, 0x08, 0x09, 0x0A});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data({0x07, 0x02, 0x03, 0x04, 0x02, 0x07, 0x07, 0x08, 0x09, 0x0A, 0x0B});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data({0x08, 0x02, 0x03, 0x04, 0x01, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data(
                {0x09, 0x02, 0x03, 0x04, 0x01, 0x07, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);
    }

    if (test_id_ == debounce_test_id_e::DTI_DECREASE) {
        auto its_payload = vsomeip::runtime::get()->create_payload();

        its_payload->set_data(
                {0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data({0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x07, 0x08, 0x09, 0x0A, 0x0B});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data({0x02, 0x02, 0x03, 0x04, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data({0x03, 0x02, 0x03, 0x04, 0x04, 0x07, 0x07, 0x08, 0x09, 0x0A});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data({0x04, 0x02, 0x03, 0x04, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0A});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data({0x05, 0x02, 0x03, 0x04, 0x03, 0x07, 0x07, 0x08, 0x09});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data({0x06, 0x02, 0x03, 0x04, 0x02, 0x06, 0x07, 0x08, 0x09});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data({0x07, 0x02, 0x03, 0x04, 0x02, 0x07, 0x07, 0x08});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data({0x08, 0x02, 0x03, 0x04, 0x01, 0x06, 0x07, 0x08});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);

        its_payload->set_data({0x09, 0x02, 0x03, 0x04, 0x01, 0x07, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_2, its_payload);
    }

    if (test_id_ == debounce_test_id_e::DTI_MASK) {
        auto its_payload = vsomeip::runtime::get()->create_payload();

        its_payload->set_data({0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_4, its_payload);

        its_payload->set_data({0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_4, its_payload);

        its_payload->set_data({0x10, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_4, its_payload);

        its_payload->set_data({0x12, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_4, its_payload);

        its_payload->set_data({0x20, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_4, its_payload);

        its_payload->set_data({0x21, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_4, its_payload);

        its_payload->set_data({0x22, 0x02, 0x03, 0x04, 0x05, 0x07, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_4, its_payload);

        its_payload->set_data({0x23, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_4, its_payload);

        its_payload->set_data({0x24, 0x02, 0x03, 0x04, 0x05, 0x07, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_4, its_payload);

        its_payload->set_data({0x25, 0x02, 0x03, 0x04, 0x05, 0x17, 0x07});
        app_->notify(DEBOUNCE_SERVICE, DEBOUNCE_INSTANCE, DEBOUNCE_EVENT_4, its_payload);
    }
}

TEST(debounce_test, flat) {
    debounce_test_service its_service(debounce_test_id_e::DTI_FLAT);
    ASSERT_TRUE(its_service.init());
    its_service.start();
    its_service.wait();
}

TEST(debounce_test, increase) {
    debounce_test_service its_service(debounce_test_id_e::DTI_INCREASE);
    ASSERT_TRUE(its_service.init());
    its_service.start();
    its_service.wait();
}

TEST(debounce_test, decrease) {
    debounce_test_service its_service(debounce_test_id_e::DTI_DECREASE);
    ASSERT_TRUE(its_service.init());
    its_service.start();
    its_service.wait();
}

TEST(debounce_test, mask) {
    debounce_test_service its_service(debounce_test_id_e::DTI_MASK);
    ASSERT_TRUE(its_service.init());
    its_service.start();
    its_service.wait();
}

int main(int argc, char** argv) {

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
