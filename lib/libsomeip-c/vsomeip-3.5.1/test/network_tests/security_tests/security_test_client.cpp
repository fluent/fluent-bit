// Copyright (C) 2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include "security_test_client.hpp"

static bool is_remote_test = false;
static bool remote_client_allowed = true;

security_test_client::security_test_client(bool _test_external_communication,
                                           bool _is_remote_client_allowed)
    : app_(vsomeip::runtime::get()->create_application()),
      is_available_(false),
      sender_(std::bind(&security_test_client::run, this)),
      received_responses_(0),
      received_allowed_events_(0),
      test_external_communication_(_test_external_communication),
      is_remote_client_allowed_(_is_remote_client_allowed) {

}

bool security_test_client::init() {
    if (!app_->init()) {
        ADD_FAILURE() << "Couldn't initialize application";
        return false;
    }

    app_->register_state_handler(
            std::bind(&security_test_client::on_state, this,
                    std::placeholders::_1));

    app_->register_message_handler(vsomeip::ANY_SERVICE,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID, vsomeip::ANY_METHOD,
            std::bind(&security_test_client::on_message, this,
                    std::placeholders::_1));

    app_->register_availability_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID,
            std::bind(&security_test_client::on_availability, this,
                    std::placeholders::_1, std::placeholders::_2,
                    std::placeholders::_3));

    app_->register_availability_handler(0x111,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID,
            std::bind(&security_test_client::on_availability, this,
                    std::placeholders::_1, std::placeholders::_2,
                    std::placeholders::_3));

    app_->register_availability_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            0x02,
            std::bind(&security_test_client::on_availability, this,
                    std::placeholders::_1, std::placeholders::_2,
                    std::placeholders::_3));
    return true;
}

void security_test_client::start() {
    VSOMEIP_INFO << "Starting...";

    app_->start();
}

void security_test_client::stop() {
    VSOMEIP_INFO << "Stopping...";

    if (is_remote_client_allowed_) {
        shutdown_service();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    app_->clear_all_handler();
    app_->stop();
}

void security_test_client::on_state(vsomeip::state_type_e _state) {
    if(_state == vsomeip::state_type_e::ST_REGISTERED) {
        app_->request_service(vsomeip_test::TEST_SERVICE_SERVICE_ID,
                vsomeip_test::TEST_SERVICE_INSTANCE_ID, false);

        // request not allowed service ID
        app_->request_service(0x111,
                vsomeip_test::TEST_SERVICE_INSTANCE_ID, false);

        // request not allowed instance ID
        app_->request_service(vsomeip_test::TEST_SERVICE_SERVICE_ID,
                0x02, false);

        // request events of eventgroup 0x01 which holds events 0x8001 (allowed) and 0x8002 (denied)
        std::set<vsomeip::eventgroup_t> its_eventgroups;
        its_eventgroups.insert(0x01);
        app_->request_event(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                static_cast<vsomeip::event_t>(0x8001),
                its_eventgroups, vsomeip::event_type_e::ET_FIELD,
                vsomeip::reliability_type_e::RT_UNRELIABLE);
        app_->request_event(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                static_cast<vsomeip::event_t>(0x8002),
                its_eventgroups, vsomeip::event_type_e::ET_FIELD,
                vsomeip::reliability_type_e::RT_UNRELIABLE);

        app_->subscribe(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID, 0x01,
                vsomeip::DEFAULT_MAJOR, static_cast<vsomeip::event_t>(0x8001));

        app_->subscribe(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID, 0x01,
                vsomeip::DEFAULT_MAJOR, static_cast<vsomeip::event_t>(0x8002));
    }
}

void security_test_client::on_availability(vsomeip::service_t _service,
        vsomeip::instance_t _instance, bool _is_available) {

    VSOMEIP_INFO << std::hex << "Client 0x" << app_->get_client()
            << " : Service [" << std::setw(4) << std::setfill('0') << std::hex
            << _service << "." << _instance << "] is "
            << (_is_available ? "available." : "NOT available.");

    // check that only the allowed service / instance ID gets available
    if (_is_available) {
        EXPECT_EQ(vsomeip_test::TEST_SERVICE_SERVICE_ID, _service);
        EXPECT_EQ(vsomeip_test::TEST_SERVICE_INSTANCE_ID, _instance);
    }

    if(vsomeip_test::TEST_SERVICE_SERVICE_ID == _service
            && vsomeip_test::TEST_SERVICE_INSTANCE_ID == _instance) {
        std::unique_lock<std::mutex> its_lock(mutex_);
        if(is_available_ && !_is_available) {
            is_available_ = false;
        }
        else if(_is_available && !is_available_) {
            is_available_ = true;
            condition_.notify_one();
        }
    }
}

void security_test_client::on_message(const std::shared_ptr<vsomeip::message> &_response) {
    VSOMEIP_INFO << "Received a response from Service ["
                 << std::setw(4) << std::setfill('0') << std::hex << _response->get_service()
                 << "."
                 << std::setw(4) << std::setfill('0') << std::hex << _response->get_instance()
                 << "] to Client/Session ["
                 << std::setw(4) << std::setfill('0') << std::hex << _response->get_client()
                 << "/"
                 << std::setw(4) << std::setfill('0') << std::hex << _response->get_session()
                 << "]";

    if(_response->get_message_type() == vsomeip::message_type_e::MT_RESPONSE) {
        EXPECT_EQ(vsomeip_test::TEST_SERVICE_SERVICE_ID,  _response->get_service());
        EXPECT_EQ(vsomeip_test::TEST_SERVICE_INSTANCE_ID, _response->get_instance());
        EXPECT_EQ(vsomeip_test::TEST_SERVICE_METHOD_ID, _response->get_method());

        if (_response->get_service() == vsomeip_test::TEST_SERVICE_SERVICE_ID &&
                _response->get_instance() == vsomeip_test::TEST_SERVICE_INSTANCE_ID &&
                _response->get_method() == vsomeip_test::TEST_SERVICE_METHOD_ID) {
            received_responses_++;
            if (received_responses_ == vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND_SECURITY_TESTS) {
                VSOMEIP_WARNING << std::hex << app_->get_client()
                        << ": Received all messages ~> going down!";
            }
        }
    } else if (_response->get_message_type() == vsomeip::message_type_e::MT_NOTIFICATION) {
        // check that only allowed event 0x8001 is received
        EXPECT_EQ(vsomeip_test::TEST_SERVICE_SERVICE_ID,  _response->get_service());
        EXPECT_EQ(vsomeip_test::TEST_SERVICE_INSTANCE_ID, _response->get_instance());
        EXPECT_EQ(0x8001, _response->get_method());
        received_allowed_events_++;
    }
}

void security_test_client::run() {
    for (uint32_t i = 0; i < vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND_SECURITY_TESTS; ++i) {
        {
            std::unique_lock<std::mutex> its_lock(mutex_);
            while (!is_available_)
            {
                condition_.wait(its_lock);
            }
        }

        auto request = vsomeip::runtime::get()->create_request(false);
        request->set_service(vsomeip_test::TEST_SERVICE_SERVICE_ID);
        request->set_instance(vsomeip_test::TEST_SERVICE_INSTANCE_ID);
        request->set_method(vsomeip_test::TEST_SERVICE_METHOD_ID);

        // send a request which is allowed by policy -> expect answer
        app_->send(request);

        // send a request with a not allowed method ID -> expect no answer
        request->set_method(0x888);
        app_->send(request);

        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    if (!test_external_communication_) {
        EXPECT_EQ(vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND_SECURITY_TESTS,
                received_responses_);
        EXPECT_EQ(received_allowed_events_, (uint32_t) 0x01);
    } else if (test_external_communication_ && !is_remote_client_allowed_) {
        EXPECT_EQ((uint32_t)0, received_responses_);
        EXPECT_EQ((uint32_t)0, received_allowed_events_);
    } else if (test_external_communication_ && is_remote_client_allowed_) {
        EXPECT_EQ(vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND_SECURITY_TESTS,
                received_responses_);
        EXPECT_EQ(received_allowed_events_, (uint32_t) 0x01);
    }
    stop();
}

void security_test_client::join_sender_thread()
{
    if (sender_.joinable()) {
        sender_.join();
    }
}

void security_test_client::shutdown_service() {
    auto request = vsomeip::runtime::get()->create_request(false);
    request->set_service(vsomeip_test::TEST_SERVICE_SERVICE_ID);
    request->set_instance(vsomeip_test::TEST_SERVICE_INSTANCE_ID);
    request->set_method(vsomeip_test::TEST_SERVICE_METHOD_ID_SHUTDOWN);
    app_->send(request);
}

TEST(someip_security_test, basic_subscribe_request_response)
{
    security_test_client test_client(is_remote_test, remote_client_allowed);
    if (test_client.init()) {
        test_client.start();
        test_client.join_sender_thread();
    }
}

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
