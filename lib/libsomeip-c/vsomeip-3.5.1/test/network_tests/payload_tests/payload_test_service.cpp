// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include "payload_test_service.hpp"

// this variables are changed via cmdline parameters

static bool check_payload = true;

payload_test_service::payload_test_service() :
                app_(vsomeip::runtime::get()->create_application()),
                is_registered_(false),
                blocked_(false),
                number_of_received_messages_(0),
                offer_thread_(std::bind(&payload_test_service::run, this))
{
}

bool payload_test_service::init()
{
    std::lock_guard<std::mutex> its_lock(mutex_);

    if (!app_->init()) {
        ADD_FAILURE() << "Couldn't initialize application";
        return false;
    }
    app_->register_message_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID, vsomeip_test::TEST_SERVICE_METHOD_ID,
            std::bind(&payload_test_service::on_message, this,
                    std::placeholders::_1));

    app_->register_message_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID,
            vsomeip_test::TEST_SERVICE_METHOD_ID_SHUTDOWN,
            std::bind(&payload_test_service::on_message_shutdown, this,
                    std::placeholders::_1));

    app_->register_state_handler(
            std::bind(&payload_test_service::on_state, this,
                    std::placeholders::_1));
    return true;
}

void payload_test_service::start()
{
    VSOMEIP_INFO << "Starting...";
    app_->start();
}

void payload_test_service::stop()
{
    VSOMEIP_INFO << "Stopping...";
    app_->clear_all_handler();
    app_->stop();
}

void payload_test_service::join_offer_thread()
{
    offer_thread_.join();
}

void payload_test_service::offer()
{
    app_->offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID);
}

void payload_test_service::stop_offer()
{
    app_->stop_offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID);
}

void payload_test_service::on_state(vsomeip::state_type_e _state)
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

void payload_test_service::on_message(const std::shared_ptr<vsomeip::message>& _request)
{
    number_of_received_messages_++;
    if(number_of_received_messages_ % vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND_PAYLOAD_TESTS == 0)
    {
        VSOMEIP_INFO << "Received a message with Client/Session [" << std::setw(4)
                << std::setfill('0') << std::hex << _request->get_client() << "/"
                << std::setw(4) << std::setfill('0') << std::hex
                << _request->get_session() << "] payload size [byte]:"
                << std::dec << _request->get_payload()->get_length();
    }

    ASSERT_EQ(vsomeip_test::TEST_SERVICE_SERVICE_ID, _request->get_service());
    ASSERT_EQ(vsomeip_test::TEST_SERVICE_METHOD_ID, _request->get_method());

    // Check the protocol version this shall be set to 0x01 according to the spec.
    // TR_SOMEIP_00052
    ASSERT_EQ(0x01, _request->get_protocol_version());
    // Check the message type this shall be 0xx (REQUEST) according to the spec.
    // TR_SOMEIP_00055
    ASSERT_EQ(vsomeip::message_type_e::MT_REQUEST, _request->get_message_type());

    if (check_payload) {
        std::shared_ptr<vsomeip::payload> pl = _request->get_payload();
        vsomeip::byte_t* pl_ptr = pl->get_data();
        for (vsomeip::length_t i = 0; i < pl->get_length(); i++)
        {
            ASSERT_EQ(vsomeip_test::PAYLOAD_TEST_DATA, *(pl_ptr+i));
        }
    }

    // send response
    std::shared_ptr<vsomeip::message> its_response =
            vsomeip::runtime::get()->create_response(_request);

    app_->send(its_response);
}

void payload_test_service::on_message_shutdown(
        const std::shared_ptr<vsomeip::message>& _request)
{
    (void)_request;
    VSOMEIP_INFO << "Shutdown method was called, going down now.";
    stop();
}

void payload_test_service::run()
{
    std::unique_lock<std::mutex> its_lock(mutex_);
    while (!blocked_)
        condition_.wait(its_lock);

   offer();
}

TEST(someip_payload_test, send_response_for_every_request)
{
    payload_test_service test_service;
    if (test_service.init()) {
        test_service.start();
        test_service.join_offer_thread();
    }
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    std::string help("--help");
    std::string check("--do-not-check-payload");

    int i = 1;
    while (i < argc)
    {
        if(help == argv[i])
        {
            VSOMEIP_INFO << "Parameters:\n"
                    << "--help: print this help\n"
                    << "--do-not-check-payload: Don't verify payload data "
                    << "-> Use this flag for performance measurements!";
        } else if (check == argv[i]) {
            check_payload = false;
        }
        i++;
    }

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
