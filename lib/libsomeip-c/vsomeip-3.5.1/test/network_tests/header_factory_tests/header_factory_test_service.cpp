// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <cstdlib>
#include <iomanip>

#include "header_factory_test_service.hpp"

header_factory_test_service::header_factory_test_service(bool _use_static_routing) :
                app_(vsomeip::runtime::get()->create_application()),
                is_registered_(false),
                use_static_routing_(_use_static_routing),
                blocked_(false),
                number_of_received_messages_(0),
                offer_thread_(std::bind(&header_factory_test_service::run, this))
{
}

bool header_factory_test_service::init()
{
    std::lock_guard<std::mutex> its_lock(mutex_);

    if (!app_->init()) {
        ADD_FAILURE() << "Couldn't initialize application";
        return false;
    }
    app_->register_message_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID, vsomeip_test::TEST_SERVICE_METHOD_ID,
            std::bind(&header_factory_test_service::on_message, this,
                    std::placeholders::_1));

    app_->register_state_handler(
            std::bind(&header_factory_test_service::on_state, this,
                    std::placeholders::_1));

    VSOMEIP_INFO << "Static routing " << (use_static_routing_ ? "ON" : "OFF");
    return true;
}

void header_factory_test_service::start()
{
    VSOMEIP_INFO << "Starting...";
    app_->start();
}

void header_factory_test_service::stop()
{
    VSOMEIP_INFO << "Stopping...";
    app_->clear_all_handler();
    app_->stop();
    std::thread t([](){ std::this_thread::sleep_for(std::chrono::microseconds(1000000 * 5));});
    t.join();
}

void header_factory_test_service::join_offer_thread()
{
    offer_thread_.join();
}

void header_factory_test_service::offer()
{
    app_->offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID);
}

void header_factory_test_service::stop_offer()
{
    app_->stop_offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID);
}

void header_factory_test_service::on_state(vsomeip::state_type_e _state)
{
    VSOMEIP_INFO << "Application " << app_->get_name() << " is "
            << (_state == vsomeip::state_type_e::ST_REGISTERED ? "registered." :
                    "deregistered.");

    if(_state == vsomeip::state_type_e::ST_REGISTERED)
    {
        if(!is_registered_)
        {
            is_registered_ = true;
            std::lock_guard<std::mutex> its_lock(mutex_);
            blocked_ = true;
            // "start" the run method thread
            condition_.notify_one();
        }
    }
    else
    {
        is_registered_ = false;
    }
}

void header_factory_test_service::on_message(const std::shared_ptr<vsomeip::message>& _request)
{
    VSOMEIP_INFO << "Received a message with Client/Session [" << std::setw(4)
            << std::setfill('0') << std::hex << _request->get_client() << "/"
            << std::setw(4) << std::setfill('0') << std::hex
            << _request->get_session() << "]";

    number_of_received_messages_++;

    ASSERT_EQ(_request->get_service(), vsomeip_test::TEST_SERVICE_SERVICE_ID);
    ASSERT_EQ(_request->get_method(), vsomeip_test::TEST_SERVICE_METHOD_ID);

    // Check the protocol version this shall be set to 0x01 according to the spec.
    // TR_SOMEIP_00052
    ASSERT_EQ(_request->get_protocol_version(), 0x01);
    // Check the message type this shall be 0xx (REQUEST) according to the spec.
    // TR_SOMEIP_00055
    ASSERT_EQ(_request->get_message_type(), vsomeip::message_type_e::MT_REQUEST);

    // check the session id.
    ASSERT_EQ(_request->get_session(), static_cast<vsomeip::session_t>(number_of_received_messages_));


    // send response
    std::shared_ptr<vsomeip::message> its_response =
            vsomeip::runtime::get()->create_response(_request);

    app_->send(its_response);

    if(number_of_received_messages_ >= vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND)
    {
        std::lock_guard<std::mutex> its_lock(mutex_);
        blocked_ =true;
        condition_.notify_one();
    }
    ASSERT_LT(number_of_received_messages_,
            vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND + 1);
}

void header_factory_test_service::run()
{
    std::unique_lock<std::mutex> its_lock(mutex_);
    while (!blocked_)
        condition_.wait(its_lock);

    blocked_ = false;
    if(use_static_routing_)
    {
        offer();
    }
    while (!blocked_)
        condition_.wait(its_lock);

    std::thread t([](){ std::this_thread::sleep_for(std::chrono::microseconds(1000000 * 5));});
    t.join();
    app_->stop();
}

TEST(someip_header_factory_test, reveice_message_ten_times_test)
{
    bool use_static_routing = true;
    header_factory_test_service test_service(use_static_routing);
    if (test_service.init()) {
        test_service.start();
        test_service.join_offer_thread();
    }
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
