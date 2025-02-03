// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include "security_test_service.hpp"

static bool is_remote_test = false;
static bool remote_client_allowed = true;

security_test_service::security_test_service() :
    app_(vsomeip::runtime::get()->create_application()),
    is_registered_(false),
    blocked_(false),
    number_of_received_messages_(0),
    offer_thread_(std::bind(&security_test_service::run, this)) {
}

bool security_test_service::init() {
    std::lock_guard<std::mutex> its_lock(mutex_);

    if (!app_->init()) {
        ADD_FAILURE() << "Couldn't initialize application";
        return false;
    }
    app_->register_message_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID, vsomeip_test::TEST_SERVICE_METHOD_ID,
            std::bind(&security_test_service::on_message, this,
                    std::placeholders::_1));

    app_->register_message_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID,
            vsomeip_test::TEST_SERVICE_METHOD_ID_SHUTDOWN,
            std::bind(&security_test_service::on_message_shutdown, this,
                    std::placeholders::_1));

    app_->register_state_handler(
            std::bind(&security_test_service::on_state, this,
                    std::placeholders::_1));

    // offer allowed field 0x8001 eventgroup 0x01
    std::set<vsomeip::eventgroup_t> its_eventgroups;
    its_eventgroups.insert(0x01);

    app_->offer_event(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                static_cast<vsomeip::event_t>(0x8001), its_eventgroups,
                vsomeip::event_type_e::ET_FIELD, std::chrono::milliseconds::zero(),
                false, true, nullptr, vsomeip::reliability_type_e::RT_UNRELIABLE);

    // also offer field 0x8002 which is not allowed to be received by client
    app_->offer_event(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                static_cast<vsomeip::event_t>(0x8002), its_eventgroups,
                vsomeip::event_type_e::ET_FIELD, std::chrono::milliseconds::zero(),
                false, true, nullptr, vsomeip::reliability_type_e::RT_UNRELIABLE);

    // set value to fields
    std::shared_ptr<vsomeip::payload> its_payload =
            vsomeip::runtime::get()->create_payload();
    vsomeip::byte_t its_data[2] = {static_cast<vsomeip::byte_t>((vsomeip_test::TEST_SERVICE_SERVICE_ID & 0xFF00) >> 8),
            static_cast<vsomeip::byte_t>((vsomeip_test::TEST_SERVICE_SERVICE_ID & 0xFF))};
    its_payload->set_data(its_data, 2);

    app_->notify(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
            static_cast<vsomeip::event_t>(0x8001), its_payload);

    app_->notify(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
            static_cast<vsomeip::event_t>(0x8002), its_payload);

    return true;
}

void security_test_service::start() {
    VSOMEIP_INFO << "Starting...";
    app_->start();
}

void security_test_service::stop() {
    VSOMEIP_INFO << "Stopping...";
    app_->clear_all_handler();
    app_->stop();
}

void security_test_service::join_offer_thread() {
    if (offer_thread_.joinable()) {
        offer_thread_.join();
    }
}

void security_test_service::offer() {
    app_->offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID);

    // try to offer a not allowed instance ID 0x02 (client requesting the service should not get available)
    app_->offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID, 0x02);

    // try to offer a not allowed service ID 0x111 (client requesting the service should not get available)
    app_->offer_service(0x111, vsomeip_test::TEST_SERVICE_INSTANCE_ID);
}

void security_test_service::stop_offer() {
    app_->stop_offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID);
}

void security_test_service::on_state(vsomeip::state_type_e _state) {
    VSOMEIP_INFO << "Application " << app_->get_name() << " is "
            << (_state == vsomeip::state_type_e::ST_REGISTERED ? "registered." :
                    "deregistered.");

    if(_state == vsomeip::state_type_e::ST_REGISTERED) {
        if(!is_registered_) {
            is_registered_ = true;
            std::lock_guard<std::mutex> its_lock(mutex_);
            blocked_ = true;
            // "start" the run method thread
            condition_.notify_one();
        }
    }
    else {
        is_registered_ = false;
    }
}

void security_test_service::on_message(const std::shared_ptr<vsomeip::message>& _request) {
    ASSERT_EQ(vsomeip_test::TEST_SERVICE_SERVICE_ID, _request->get_service());
    ASSERT_EQ(vsomeip_test::TEST_SERVICE_INSTANCE_ID, _request->get_instance());

    VSOMEIP_INFO << "Received a message with Client/Session [" << std::setw(4)
        << std::setfill('0') << std::hex << _request->get_client() << "/"
        << std::setw(4) << std::setfill('0') << std::hex
        << _request->get_session() << "] method: " << _request->get_method() ;

    // send response
    std::shared_ptr<vsomeip::message> its_response =
            vsomeip::runtime::get()->create_response(_request);

    app_->send(its_response);

    number_of_received_messages_++;
    if(number_of_received_messages_ == vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND_SECURITY_TESTS) {
        VSOMEIP_INFO << "Received all messages!";
    }
}

void security_test_service::on_message_shutdown(
        const std::shared_ptr<vsomeip::message>& _request) {
    (void)_request;
    VSOMEIP_INFO << "Shutdown method was called, going down now.";
    stop();
}

void security_test_service::run() {
    std::unique_lock<std::mutex> its_lock(mutex_);
    while (!blocked_)
        condition_.wait(its_lock);

   offer();

   // do not wait for the shutdown method to be called
   if (is_remote_test && !remote_client_allowed) {
       std::this_thread::sleep_for(std::chrono::milliseconds(250 * vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND_SECURITY_TESTS + 10000));
       VSOMEIP_INFO << "Shutdown the service after timeout as remote client is not allowed by policy to call shutdown method!";
       stop();
   }

}

TEST(someip_security_test, basic_subscribe_request_response) {
    security_test_service test_service;
    if (test_service.init()) {
        test_service.start();
        test_service.join_offer_thread();
    }
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv) {

    std::string test_remote("--remote");
    std::string test_local("--local");
    std::string test_allow_remote_client("--allow");
    std::string test_deny_remote_client("--deny");
    std::string help("--help");

    int i = 1;
    while (i < argc)
    {
        if(test_remote == argv[i])
        {
            is_remote_test = true;
        }
        else if(test_local == argv[i])
        {
            is_remote_test = false;
        }
        else if(test_allow_remote_client == argv[i])
        {
            remote_client_allowed = true;
        }
        else if(test_deny_remote_client == argv[i])
        {
            remote_client_allowed = false;
        }
        else if(help == argv[i])
        {
            VSOMEIP_INFO << "Parameters:\n"
            << "--remote: Run test between two hosts\n"
            << "--local: Run test locally\n"
            << "--allow: test is started with a policy that allows remote messages sent by this test client to the service\n"
            << "--deny: test is started with a policy that denies remote messages sent by this test client to the service\n"
            << "--help: print this help";
        }
        i++;
    }

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
