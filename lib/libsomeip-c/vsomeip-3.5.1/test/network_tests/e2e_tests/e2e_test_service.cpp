// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include "e2e_test_service.hpp"

static bool is_remote_test = false;
static bool remote_client_allowed = true;

std::vector<std::vector<vsomeip::byte_t>> payloads_profile_01_;
std::vector<std::vector<vsomeip::byte_t>> payloads_custom_profile_;
std::map<vsomeip::method_t, uint32_t> received_requests_counters_;

e2e_test_service::e2e_test_service() :
    app_(vsomeip::runtime::get()->create_application()),
    is_registered_(false),
    blocked_(false),
    number_of_received_messages_(0),
    offer_thread_(std::bind(&e2e_test_service::run, this)) {
}

bool e2e_test_service::init() {
    std::lock_guard<std::mutex> its_lock(mutex_);

    if (!app_->init()) {
        ADD_FAILURE() << "Couldn't initialize application";
        return false;
    }
    // profile01 CRC8 Method ID: 0x8421
    app_->register_message_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID, vsomeip_test::TEST_SERVICE_METHOD_ID,
            std::bind(&e2e_test_service::on_message, this,
                    std::placeholders::_1));

    // custom profile CRC32 Method ID: 0x6543
    app_->register_message_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID, 0x6543,
            std::bind(&e2e_test_service::on_message, this,
                    std::placeholders::_1));

    app_->register_message_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID,
            vsomeip_test::TEST_SERVICE_METHOD_ID_SHUTDOWN,
            std::bind(&e2e_test_service::on_message_shutdown, this,
                    std::placeholders::_1));

    app_->register_state_handler(
            std::bind(&e2e_test_service::on_state, this,
                    std::placeholders::_1));

    // offer field 0x8001 eventgroup 0x01
    std::set<vsomeip::eventgroup_t> its_eventgroups;
    its_eventgroups.insert(0x01);

    // offer field 0x8002 eventgroup 0x02
    std::set<vsomeip::eventgroup_t> its_eventgroups_2;
    its_eventgroups_2.insert(0x02);

    // profile01 CRC8 Event ID: 0x8001
    app_->offer_event(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                static_cast<vsomeip::event_t>(0x8001), its_eventgroups,
                vsomeip::event_type_e::ET_FIELD, std::chrono::milliseconds::zero(),
                false, true, nullptr, vsomeip::reliability_type_e::RT_UNRELIABLE);

    // set value to field which gets filled by e2e protection  with CRC on sending
    // after e2e protection the payload for first event should look like:
    // {{0xa4, 0xa1, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff}
    std::shared_ptr<vsomeip::payload> its_payload =
            vsomeip::runtime::get()->create_payload();
    vsomeip::byte_t its_data[8] = {0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff};
    its_payload->set_data(its_data, 8);

    app_->notify(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
            static_cast<vsomeip::event_t>(0x8001), its_payload);

    // custom profile CRC32 Event ID: 0x8002
    app_->offer_event(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                static_cast<vsomeip::event_t>(0x8002), its_eventgroups_2,
                vsomeip::event_type_e::ET_FIELD, std::chrono::milliseconds::zero(),
                false, true, nullptr, vsomeip::reliability_type_e::RT_UNRELIABLE);

    // set value to field which gets filled by e2e protection  with CRC on sending
    // after e2e protection the payload for first event should look like:
    // {{0x89, 0x0e, 0xbc, 0x80, 0xff, 0xff, 0x00, 0x32}
    std::shared_ptr<vsomeip::payload> its_payload_8002 =
            vsomeip::runtime::get()->create_payload();
    vsomeip::byte_t its_data_8002[8] = {0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x32};
    its_payload_8002->set_data(its_data_8002, 8);

    app_->notify(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
            static_cast<vsomeip::event_t>(0x8002), its_payload_8002);

    return true;
}

void e2e_test_service::start() {
    VSOMEIP_INFO << "Starting...";
    app_->start();
}

void e2e_test_service::stop() {
    VSOMEIP_INFO << "Stopping...";
    app_->clear_all_handler();
    app_->stop();
}

void e2e_test_service::join_offer_thread() {
    if (offer_thread_.joinable()) {
        offer_thread_.join();
    }
}

void e2e_test_service::offer() {
    app_->offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID);
}

void e2e_test_service::stop_offer() {
    app_->stop_offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID);
}

void e2e_test_service::on_state(vsomeip::state_type_e _state) {
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

void e2e_test_service::on_message(const std::shared_ptr<vsomeip::message>& _request) {
    ASSERT_EQ(vsomeip_test::TEST_SERVICE_SERVICE_ID, _request->get_service());
    ASSERT_EQ(vsomeip_test::TEST_SERVICE_INSTANCE_ID, _request->get_instance());

    VSOMEIP_INFO << "Received a message with Client/Session [" << std::setw(4)
        << std::setfill('0') << std::hex << _request->get_client() << "/"
        << std::setw(4) << std::setfill('0') << std::hex
        << _request->get_session() << "] method: " << _request->get_method() ;

    std::shared_ptr<vsomeip::message> its_response =
            vsomeip::runtime::get()->create_response(_request);
    std::shared_ptr< vsomeip::payload > its_vsomeip_payload =
            vsomeip::runtime::get()->create_payload();
    std::shared_ptr<vsomeip::payload> its_event_payload =
            vsomeip::runtime::get()->create_payload();

    // send fixed payload for profile 01 CRC8
    if (_request->get_method() == vsomeip_test::TEST_SERVICE_METHOD_ID) {
        its_vsomeip_payload->set_data(payloads_profile_01_[received_requests_counters_[vsomeip_test::TEST_SERVICE_METHOD_ID] % vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND]);
        its_response->set_payload(its_vsomeip_payload);
        app_->send(its_response);

        // set value to field which gets filled by e2e protection with CRC on sending
        vsomeip::byte_t its_data[8] = {0x00, 0x00, (uint8_t)received_requests_counters_[vsomeip_test::TEST_SERVICE_METHOD_ID], 0xff, 0xff, 0xff, 0xff, 0xff};
        its_event_payload->set_data(its_data, 8);
        app_->notify(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                static_cast<vsomeip::event_t>(0x8001), its_event_payload);
        received_requests_counters_[vsomeip_test::TEST_SERVICE_METHOD_ID]++;
    } else if (_request->get_method() == 0x6543) {
        //send fixed payload for custom profile CRC32
        its_vsomeip_payload->set_data(payloads_custom_profile_[received_requests_counters_[0x6543] % vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND]);
        its_response->set_payload(its_vsomeip_payload);
        app_->send(its_response);

        // set value to field which gets filled by e2e protection with 4 byte CRC 32 on sending
        vsomeip::byte_t its_data[8] = {0x00, 0x00, 0x00, 0x00, 0xff, 0xff, (uint8_t)received_requests_counters_[0x6543], 0x32};
        its_event_payload->set_data(its_data, 8);
        app_->notify(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                static_cast<vsomeip::event_t>(0x8002), its_event_payload);
        received_requests_counters_[0x6543]++;
    }

    number_of_received_messages_++;
    if(number_of_received_messages_ == vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND * 2) {
        VSOMEIP_INFO << "Received all messages!";
    }
}

void e2e_test_service::on_message_shutdown(
        const std::shared_ptr<vsomeip::message>& _request) {
    (void)_request;
    VSOMEIP_INFO << "Shutdown method was called, going down now.";
    stop();
}

void e2e_test_service::run() {
    std::unique_lock<std::mutex> its_lock(mutex_);
    while (!blocked_)
        condition_.wait(its_lock);
   offer();
}

TEST(someip_e2e_test, basic_subscribe_request_response) {
    e2e_test_service test_service;
    if (test_service.init()) {
        test_service.start();
        test_service.join_offer_thread();
    }
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv) {

    /*
     e2e profile01 CRC8 protected sample payloads using the following config at receiver:
    "service_id" : "0x1234",
    "event_id" : "0x8421",
    "profile" : "CRC8",
    "variant" : "checker",
    "crc_offset" : "0",
    "data_id_mode" : "3",
    "data_length" : "56",
    "data_id" : "0xA73"
     */
    payloads_profile_01_.push_back({{0x82, 0xa4, 0xe3, 0xff, 0xff, 0xff, 0xff, 0xff}});
    payloads_profile_01_.push_back({{0x39, 0xa8, 0xe3, 0xff, 0xff, 0xff, 0xff, 0xff}});
    payloads_profile_01_.push_back({{0x87, 0xa4, 0xe7, 0xff, 0xff, 0xff, 0xff, 0xff}});
    payloads_profile_01_.push_back({{0x3c, 0xa8, 0xe7, 0xff, 0xff, 0xff, 0xff, 0xff}});
    payloads_profile_01_.push_back({{0x55, 0xac, 0xe7, 0xff, 0xff, 0xff, 0xff, 0xff}});
    payloads_profile_01_.push_back({{0x82, 0xa4, 0xe3, 0xff, 0xff, 0xff, 0xff, 0xff}});
    payloads_profile_01_.push_back({{0x39, 0xa8, 0xe3, 0xff, 0xff, 0xff, 0xff, 0xff}});
    payloads_profile_01_.push_back({{0x87, 0xa4, 0xe7, 0xff, 0xff, 0xff, 0xff, 0xff}});
    payloads_profile_01_.push_back({{0x3c, 0xa8, 0xe7, 0xff, 0xff, 0xff, 0xff, 0xff}});
    payloads_profile_01_.push_back({{0x55, 0xac, 0xe7, 0xff, 0xff, 0xff, 0xff, 0xff}});

    /*
     e2e custom profile CRC32 protected sample payloads using the following config at receiver:
    "service_id" : "0x1234",
    "event_id" : "0x6543",
    "profile" : "CRC32",
    "variant" : "checker",
    "crc_offset" : "0"
     */
    payloads_custom_profile_.push_back({{0xa4, 0xb2, 0x75, 0x1f, 0xff, 0x00, 0xff, 0x32}});
    payloads_custom_profile_.push_back({{0xa5, 0x70, 0x1f, 0x28, 0xff, 0x01, 0xff, 0x32}});
    payloads_custom_profile_.push_back({{0xa7, 0x36, 0xa1, 0x71, 0xff, 0x02, 0xff, 0x32}});
    payloads_custom_profile_.push_back({{0xa6, 0xf4, 0xcb, 0x46, 0xff, 0x03, 0xff, 0x32}});
    payloads_custom_profile_.push_back({{0xa3, 0xbb, 0xdd, 0xc3, 0xff, 0x04, 0xff, 0x32}});
    payloads_custom_profile_.push_back({{0xa2, 0x79, 0xb7, 0xf4, 0xff, 0x05, 0xff, 0x32}});
    payloads_custom_profile_.push_back({{0xa0, 0x3f, 0x09, 0xad, 0xff, 0x06, 0xff, 0x32}});
    payloads_custom_profile_.push_back({{0xa1, 0xfd, 0x63, 0x9a, 0xff, 0x07, 0xff, 0x32}});
    payloads_custom_profile_.push_back({{0xaa, 0xa1, 0x24, 0xa7, 0xff, 0x08, 0xff, 0x32}});
    payloads_custom_profile_.push_back({{0xab, 0x63, 0x4e, 0x90, 0xff, 0x09, 0xff, 0x32}});

    received_requests_counters_[vsomeip_test::TEST_SERVICE_METHOD_ID] = 0;
    received_requests_counters_[0x7654] = 0;
    received_requests_counters_[0x6543] = 0;
    received_requests_counters_[0x5432] = 0;

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
