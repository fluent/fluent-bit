// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include "e2e_profile_04_test_common.hpp"
#include "e2e_profile_04_test_service.hpp"

static bool is_remote_test = false;
static bool remote_client_allowed = true;

std::vector<std::vector<vsomeip::byte_t> > responses_;
std::vector<std::vector<vsomeip::byte_t> > events_;

std::map<vsomeip::method_t, uint32_t> counters_;

e2e_profile_04_test_service::e2e_profile_04_test_service()
    : app_(vsomeip::runtime::get()->create_application()),
      is_registered_(false),
      blocked_(false),
      offer_thread_(std::bind(&e2e_profile_04_test_service::run, this)),
      received_(0) {
}

bool
e2e_profile_04_test_service::init() {

    std::lock_guard<std::mutex> its_lock(mutex_);

    if (!app_->init()) {
        ADD_FAILURE() << __func__ << ": Cannot initialize application.";
        return false;
    }

    app_->register_message_handler(PROFILE_04_SERVICE, PROFILE_04_INSTANCE,
            PROFILE_04_METHOD,
            std::bind(&e2e_profile_04_test_service::on_message, this,
                    std::placeholders::_1));

    app_->register_message_handler(PROFILE_04_SERVICE, PROFILE_04_INSTANCE,
            PROFILE_04_SHUTDOWN,
            std::bind(&e2e_profile_04_test_service::on_message_shutdown, this,
                    std::placeholders::_1));

    app_->register_state_handler(
            std::bind(&e2e_profile_04_test_service::on_state, this,
                    std::placeholders::_1));

    // E2E Profile 04: Event 8001
    app_->offer_event(PROFILE_04_SERVICE, PROFILE_04_INSTANCE,
            PROFILE_04_EVENT, { PROFILE_04_EVENTGROUP },
            vsomeip::event_type_e::ET_FIELD, std::chrono::milliseconds::zero(),
            false, true, nullptr, vsomeip::reliability_type_e::RT_UNRELIABLE);

    // Initialize the attribute
    auto its_payload = vsomeip::runtime::get()->create_payload();
    vsomeip::byte_t its_data[] = {
            0x00, 0x50, 0x8f, 0x80, 0x01, 0x00, 0x00, 0x2d,
            0xf3, 0x2a, 0x8c, 0x89, 0x05, 0x04, 0xcc, 0x46,
            0x00, 0x00, 0x09, 0x3d, 0x00, 0x01, 0x06, 0xfe,
            0x01, 0x3e, 0x4c, 0xcc, 0xcd, 0x80, 0x3f, 0xb2,
            0x40, 0xb1, 0x3e, 0xba, 0xc4, 0x76, 0x3f, 0xb3,
            0x7b, 0x03, 0xbd, 0x95, 0x74, 0x53, 0x3d, 0x32,
            0x4b, 0x9d, 0xbd, 0xbc, 0xd6, 0x3b, 0x3f, 0x80,
            0x00, 0x00, 0xfc, 0x01, 0x01, 0x3c, 0x1f, 0xf5,
            0xf6, 0x01, 0x01, 0x3c, 0x2b, 0xb1, 0xa2, 0x00
    };
    its_payload->set_data(its_data, sizeof(its_data));

    app_->notify(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
            static_cast<vsomeip::event_t>(0x8001), its_payload);

    return true;
}

void
e2e_profile_04_test_service::start() {

    VSOMEIP_INFO << __func__ << ": Starting...";
    app_->start();
}

void
e2e_profile_04_test_service::stop() {

    VSOMEIP_INFO << __func__ << ": Stopping...";
    app_->clear_all_handler();
    app_->stop();
}

void
e2e_profile_04_test_service::join_offer_thread() {

    if (offer_thread_.joinable()) {
        offer_thread_.join();
    }
}

void
e2e_profile_04_test_service::offer() {

    app_->offer_service(PROFILE_04_SERVICE, PROFILE_04_INSTANCE,
            PROFILE_04_MAJOR, PROFILE_04_MINOR);
}

void
e2e_profile_04_test_service::stop_offer() {

    app_->stop_offer_service(PROFILE_04_SERVICE, PROFILE_04_INSTANCE,
            PROFILE_04_MAJOR, PROFILE_04_MINOR);
}

void
e2e_profile_04_test_service::on_state(vsomeip::state_type_e _state) {

    VSOMEIP_INFO << __func__ << ": Application "
            << app_->get_name() << " is "
            << (_state == vsomeip::state_type_e::ST_REGISTERED ?
                    "registered." : "deregistered.");

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

void
e2e_profile_04_test_service::on_message(
        const std::shared_ptr<vsomeip::message> &_request) {

    ASSERT_EQ(PROFILE_04_SERVICE, _request->get_service());
    ASSERT_EQ(PROFILE_04_INSTANCE, _request->get_instance());

    VSOMEIP_INFO << "Received a message with Client/Session ["
            << std::setw(4) << std::setfill('0') << std::hex
            << _request->get_client() << "/" << _request->get_session()
            << "] method: " << _request->get_method() ;

    std::shared_ptr<vsomeip::message> its_response =
            vsomeip::runtime::get()->create_response(_request);
    std::shared_ptr< vsomeip::payload > its_response_payload =
            vsomeip::runtime::get()->create_payload();
    std::shared_ptr<vsomeip::payload> its_event_payload =
            vsomeip::runtime::get()->create_payload();

    // send fixed payload for profile 01 CRC8
    if (PROFILE_04_METHOD == _request->get_method()) {
        its_response_payload->set_data(responses_[counters_[PROFILE_04_METHOD] % PROFILE_O4_NUM_MESSAGES]);
        its_response->set_payload(its_response_payload);
        app_->send(its_response);

        counters_[PROFILE_04_METHOD]++;

        // set value to field which gets filled by e2e protection with CRC on sending
        its_event_payload->set_data(events_[counters_[PROFILE_04_EVENT] % PROFILE_O4_NUM_MESSAGES]);
        app_->notify(PROFILE_04_SERVICE, PROFILE_04_INSTANCE, PROFILE_04_EVENT, its_event_payload);

        counters_[PROFILE_04_EVENT]++;
    }

    received_++;
    if (received_ == PROFILE_O4_NUM_MESSAGES) {
        VSOMEIP_INFO << __func__ << ": Received all messages!";
    }
}

void
e2e_profile_04_test_service::on_message_shutdown(
        const std::shared_ptr<vsomeip::message> &_request) {

    (void)_request;
    VSOMEIP_INFO << __func__ << ": Shutdown method was called, going down now.";
    stop();
}

void
e2e_profile_04_test_service::run() {

    std::unique_lock<std::mutex> its_lock(mutex_);
    while (!blocked_)
        condition_.wait(its_lock);

    offer();
}

TEST(someip_e2e_profile_04_test, basic_subscribe_request_response) {
    e2e_profile_04_test_service test_service;
    if (test_service.init()) {
        test_service.start();
        test_service.join_offer_thread();
    }
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv) {


    counters_[PROFILE_04_METHOD] = 0;
    counters_[PROFILE_04_EVENT] = 0;

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

    // Payloads (without counter, data id and crc)
    responses_ = {
        {
            0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x08, 0xb7, 0xf4, 0x4c,
            0x00, 0x00, 0x09, 0x3d, 0x00, 0x01, 0x06, 0xfe,
            0x01, 0x3e, 0x4c, 0xcc, 0xcd, 0x80, 0x3f, 0xb2,
            0x3d, 0x83, 0x3e, 0xba, 0x68, 0xed, 0x3f, 0xb3,
            0x7a, 0xf2, 0xbd, 0x96, 0xc1, 0x42, 0x3d, 0x25,
            0x1a, 0x62, 0xbd, 0xae, 0x77, 0xf3, 0x3f, 0x80,
            0x00, 0x00, 0xfc, 0x01, 0x01, 0x3c, 0x1d, 0xbd,
            0x4e, 0x01, 0x01, 0x3c, 0x2b, 0x87, 0xed, 0x00
        },
        {
            0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x0c, 0x69, 0x02, 0x1c,
            0x00, 0x00, 0x09, 0x3d, 0x00, 0x01, 0x06, 0xfe,
            0x01, 0x3e, 0x4c, 0xcc, 0xcd, 0x80, 0x3f, 0xb2,
            0x3c, 0x2f, 0x3e, 0xba, 0x46, 0x81, 0x3f, 0xb3,
            0x73, 0x8d, 0xbd, 0x93, 0xcb, 0xae, 0x3c, 0xf7,
            0xd2, 0x58, 0xbd, 0xa2, 0x6e, 0xcd, 0x3f, 0x80,
            0x00, 0x00, 0xfc, 0x01, 0x01, 0x3c, 0x1c, 0x89,
            0x24, 0x01, 0x01, 0x3c, 0x2b, 0x24, 0x45, 0x00
        },
        {
            0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x10, 0x1b, 0x28, 0xae,
            0x00, 0x00, 0x09, 0x3d, 0x00, 0x01, 0x06, 0xfe,
            0x01, 0x3e, 0x4c, 0xcc, 0xcd, 0x80, 0x3f, 0xb2,
            0x3e, 0xf3, 0x3e, 0xba, 0x97, 0x45, 0x3f, 0xb3,
            0x86, 0x81, 0xbd, 0x8a, 0xda, 0xc2, 0x3c, 0xf6,
            0x00, 0x7a, 0xbd, 0xb4, 0xf9, 0xb9, 0x3f, 0x80,
            0x00, 0x00, 0xfc, 0x01, 0x01, 0x3c, 0x1c, 0x1b,
            0x72, 0x01, 0x01, 0x3c, 0x2a, 0x9e, 0x1f, 0x00
        }
    };

    // Payloads (full data with counter, data id and crc to be sent raw)
    events_ = {
        {
            0x00, 0x50, 0x8f, 0x81, 0x01, 0x00, 0x00, 0x2d,
            0xed, 0x6e, 0x78, 0x8d, 0x08, 0xb7, 0xf4, 0x4c,
            0x00, 0x00, 0x09, 0x3d, 0x00, 0x01, 0x06, 0xfe,
            0x01, 0x3e, 0x4c, 0xcc, 0xcd, 0x80, 0x3f, 0xb2,
            0x3d, 0x83, 0x3e, 0xba, 0x68, 0xed, 0x3f, 0xb3,
            0x7a, 0xf2, 0xbd, 0x96, 0xc1, 0x42, 0x3d, 0x25,
            0x1a, 0x62, 0xbd, 0xae, 0x77, 0xf3, 0x3f, 0x80,
            0x00, 0x00, 0xfc, 0x01, 0x01, 0x3c, 0x1d, 0xbd,
            0x4e, 0x01, 0x01, 0x3c, 0x2b, 0x87, 0xed, 0x00
        },
        {
            0x00, 0x50, 0x8f, 0x82, 0x01, 0x00, 0x00, 0x2d,
            0x9d, 0xbb, 0x49, 0x3f, 0x0c, 0x69, 0x02, 0x1c,
            0x00, 0x00, 0x09, 0x3d, 0x00, 0x01, 0x06, 0xfe,
            0x01, 0x3e, 0x4c, 0xcc, 0xcd, 0x80, 0x3f, 0xb2,
            0x3c, 0x2f, 0x3e, 0xba, 0x46, 0x81, 0x3f, 0xb3,
            0x73, 0x8d, 0xbd, 0x93, 0xcb, 0xae, 0x3c, 0xf7,
            0xd2, 0x58, 0xbd, 0xa2, 0x6e, 0xcd, 0x3f, 0x80,
            0x00, 0x00, 0xfc, 0x01, 0x01, 0x3c, 0x1c, 0x89,
            0x24, 0x01, 0x01, 0x3c, 0x2b, 0x24, 0x45, 0x00
        },
        {
            0x00, 0x50, 0x8f, 0x83, 0x01, 0x00, 0x00, 0x2d,
            0x13, 0x04, 0xf8, 0x81, 0x10, 0x1b, 0x28, 0xae,
            0x00, 0x00, 0x09, 0x3d, 0x00, 0x01, 0x06, 0xfe,
            0x01, 0x3e, 0x4c, 0xcc, 0xcd, 0x80, 0x3f, 0xb2,
            0x3e, 0xf3, 0x3e, 0xba, 0x97, 0x45, 0x3f, 0xb3,
            0x86, 0x81, 0xbd, 0x8a, 0xda, 0xc2, 0x3c, 0xf6,
            0x00, 0x7a, 0xbd, 0xb4, 0xf9, 0xb9, 0x3f, 0x80,
            0x00, 0x00, 0xfc, 0x01, 0x01, 0x3c, 0x1c, 0x1b,
            0x72, 0x01, 0x01, 0x3c, 0x2a, 0x9e, 0x1f, 0x00
        }
    };

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
