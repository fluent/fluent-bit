// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include "lazy_load_test_service.hpp"

lazy_load_test_service::lazy_load_test_service() :
    app_(vsomeip::runtime::get()->create_application()),
    is_registered_(false),
    blocked_(false),
    number_of_received_messages_(0),
    offer_thread_(std::bind(&lazy_load_test_service::run, this)) {}

bool lazy_load_test_service::init() {
    std::lock_guard<std::mutex> its_lock(mutex_);

    if (!app_->init()) {
        ADD_FAILURE() << "Couldn't initialize application";
        return false;
    }
    app_->register_message_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID, vsomeip_test::TEST_SERVICE_METHOD_ID,
            std::bind(&lazy_load_test_service::on_message, this,
                    std::placeholders::_1));

    app_->register_message_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            TEST_INSTANCE_LAZY,
            vsomeip_test::TEST_SERVICE_METHOD_ID_SHUTDOWN,
            std::bind(&lazy_load_test_service::on_message_shutdown, this,
                    std::placeholders::_1));

    app_->register_message_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            TEST_INSTANCE_LAZY,
            vsomeip_test::TEST_SERVICE_METHOD_ID,
            std::bind(&lazy_load_test_service::on_message, this,
                    std::placeholders::_1));

    app_->register_state_handler(
            std::bind(&lazy_load_test_service::on_state, this,
                    std::placeholders::_1));

    // offer eventgroup 0x01
    std::set<vsomeip::eventgroup_t> its_eventgroups;
    its_eventgroups.insert(EVENT_GROUP);

    app_->offer_event(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                static_cast<vsomeip::event_t>(EVENT_TO_ACCEPT_DEFAULT), its_eventgroups,
                vsomeip::event_type_e::ET_FIELD, std::chrono::milliseconds::zero(),
                false, true, nullptr, vsomeip::reliability_type_e::RT_UNRELIABLE);

    // also offer field 0x8002 which is not allowed to be received by client
    app_->offer_event(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                static_cast<vsomeip::event_t>(EVENT_TO_ACCEPT_LAZY), its_eventgroups,
                vsomeip::event_type_e::ET_FIELD, std::chrono::milliseconds::zero(),
                false, true, nullptr, vsomeip::reliability_type_e::RT_UNRELIABLE);

    // Used with lazy client also offer field 0x8001 which is not allowed to be received by lazy client
    app_->offer_event(vsomeip_test::TEST_SERVICE_SERVICE_ID, TEST_INSTANCE_LAZY,
                static_cast<vsomeip::event_t>(EVENT_TO_ACCEPT_DEFAULT), its_eventgroups,
                vsomeip::event_type_e::ET_FIELD, std::chrono::milliseconds::zero(),
                false, true, nullptr, vsomeip::reliability_type_e::RT_UNRELIABLE);

    app_->offer_event(vsomeip_test::TEST_SERVICE_SERVICE_ID, TEST_INSTANCE_LAZY,
                static_cast<vsomeip::event_t>(EVENT_TO_ACCEPT_LAZY), its_eventgroups,
                vsomeip::event_type_e::ET_FIELD, std::chrono::milliseconds::zero(),
                false, true, nullptr, vsomeip::reliability_type_e::RT_UNRELIABLE);

    // set value to fields
    std::shared_ptr<vsomeip::payload> its_payload =
            vsomeip::runtime::get()->create_payload();
    vsomeip::byte_t its_data[2]{
        static_cast<vsomeip::byte_t>((vsomeip_test::TEST_SERVICE_SERVICE_ID & 0xFF00) >> 8),
        static_cast<vsomeip::byte_t>((vsomeip_test::TEST_SERVICE_SERVICE_ID & 0xFF))
    };
    its_payload->set_data(its_data, 2);

    app_->notify(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
            static_cast<vsomeip::event_t>(EVENT_TO_ACCEPT_DEFAULT), its_payload);

    app_->notify(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
            static_cast<vsomeip::event_t>(EVENT_TO_ACCEPT_LAZY), its_payload);

    app_->notify(vsomeip_test::TEST_SERVICE_SERVICE_ID, TEST_INSTANCE_LAZY,
            static_cast<vsomeip::event_t>(EVENT_TO_ACCEPT_DEFAULT), its_payload);

    app_->notify(vsomeip_test::TEST_SERVICE_SERVICE_ID, TEST_INSTANCE_LAZY,
            static_cast<vsomeip::event_t>(EVENT_TO_ACCEPT_LAZY), its_payload);

    return true;
}

void lazy_load_test_service::start() {
    VSOMEIP_INFO << "Starting...";
    app_->start();
}

void lazy_load_test_service::stop() {
    VSOMEIP_INFO << "Stopping...";
    stop_offer();
    app_->clear_all_handler();
    app_->stop();
}

void lazy_load_test_service::join_offer_thread() {
    if (offer_thread_.joinable()) {
        offer_thread_.join();
    }
}

void lazy_load_test_service::offer() {
    // Instance used by client a
    app_->offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID);

    // Instance used by client b
    app_->offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID, TEST_INSTANCE_LAZY);

    // try to offer a not allowed service ID 0x111 (client requesting the service should not get available)
    app_->offer_service(SERVICE_TO_BE_REFUSED, vsomeip_test::TEST_SERVICE_INSTANCE_ID);
}

void lazy_load_test_service::stop_offer() {
    app_->stop_offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID);
    app_->stop_offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID, TEST_INSTANCE_LAZY);
}

void lazy_load_test_service::on_state(vsomeip::state_type_e _state) {
    VSOMEIP_INFO << "Application " << app_->get_name() << " is "
            << (_state == vsomeip::state_type_e::ST_REGISTERED ? "registered." :
                    "deregistered.");

    if (_state == vsomeip::state_type_e::ST_REGISTERED) {
        if (!is_registered_) {
            is_registered_ = true;
            std::lock_guard<std::mutex> its_lock(mutex_);
            blocked_ = true;
            // "start" the run method thread
            condition_.notify_one();
        }
    } else {
        is_registered_ = false;
    }
}

void lazy_load_test_service::on_message(const std::shared_ptr<vsomeip::message>& _request) {
    ASSERT_EQ(vsomeip_test::TEST_SERVICE_SERVICE_ID, _request->get_service());
    ASSERT_EQ(vsomeip_test::TEST_SERVICE_METHOD_ID, _request->get_method());

    VSOMEIP_INFO << "Received a message with Client/Session [" << std::setw(4)
        << std::setfill('0') << std::hex << _request->get_client() << '/'
        << std::setw(4) << std::setfill('0') << std::hex
        << _request->get_session() << "] method: " << _request->get_method()
        << " Instance ID: " << _request->get_instance();

    // send response
    std::shared_ptr<vsomeip::message> its_response =
            vsomeip::runtime::get()->create_response(_request);

    VSOMEIP_INFO << "service on_message response service : " << its_response->get_service();
    app_->send(its_response);

    number_of_received_messages_++;
    if (number_of_received_messages_ == NUMBER_OF_MESSAGES_TO_RECEIVE) {
        VSOMEIP_INFO << "Received all messages!";
    }
}

void lazy_load_test_service::on_message_shutdown(
        const std::shared_ptr<vsomeip::message>&) {
    VSOMEIP_INFO << "Shutdown method was called, going down now.";
    stop();
}

void lazy_load_test_service::run() {
    std::unique_lock<std::mutex> its_lock(mutex_);
    while (!blocked_)
        condition_.wait(its_lock);

   offer();
}

TEST(someip_lazy_load_test, service) {
    lazy_load_test_service test_service;
    if (test_service.init()) {
        test_service.start();
        test_service.join_offer_thread();
    }
}

#ifdef __linux__
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
