// Copyright (C) 2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include "e2e_test_client.hpp"

static bool is_remote_test = false;
static bool remote_client_allowed = true;
std::vector<std::vector<vsomeip::byte_t>> payloads_profile_01_;
std::vector<std::vector<vsomeip::byte_t>> event_payloads_profile_01_;

std::vector<std::vector<vsomeip::byte_t>> payloads_custom_profile_;
std::vector<std::vector<vsomeip::byte_t>> event_payloads_custom_profile_;

std::map<vsomeip::method_t, uint32_t> received_responses_counters_;


e2e_test_client::e2e_test_client(bool _test_external_communication,
                                           bool _is_remote_client_allowed)
    : app_(vsomeip::runtime::get()->create_application()),
      is_available_(false),
      sender_(std::bind(&e2e_test_client::run, this)),
      received_responses_(0),
      received_allowed_events_(0),
      test_external_communication_(_test_external_communication),
      is_remote_client_allowed_(_is_remote_client_allowed) {

}

bool e2e_test_client::init() {
    if (!app_->init()) {
        ADD_FAILURE() << "Couldn't initialize application";
        return false;
    }

    app_->register_state_handler(
            std::bind(&e2e_test_client::on_state, this,
                    std::placeholders::_1));

    app_->register_message_handler(vsomeip::ANY_SERVICE,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID, vsomeip::ANY_METHOD,
            std::bind(&e2e_test_client::on_message, this,
                    std::placeholders::_1));

    app_->register_availability_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID,
            std::bind(&e2e_test_client::on_availability, this,
                    std::placeholders::_1, std::placeholders::_2,
                    std::placeholders::_3));
    return true;
}

void e2e_test_client::start() {
    VSOMEIP_INFO << "Starting...";
    app_->start();
}

void e2e_test_client::stop() {
    VSOMEIP_INFO << "Stopping...";
    shutdown_service();
    app_->clear_all_handler();
    app_->stop();
}

void e2e_test_client::on_state(vsomeip::state_type_e _state) {
    if(_state == vsomeip::state_type_e::ST_REGISTERED) {
        app_->request_service(vsomeip_test::TEST_SERVICE_SERVICE_ID,
                vsomeip_test::TEST_SERVICE_INSTANCE_ID, false);

        // request events of eventgroup 0x01 which holds events 0x8001 (CRC8)
        std::set<vsomeip::eventgroup_t> its_eventgroups;
        its_eventgroups.insert(0x01);

        // request events of eventgroup 0x02 which holds events 0x8002 (CRC32)
        std::set<vsomeip::eventgroup_t> its_eventgroups_2;
        its_eventgroups_2.insert(0x02);

        app_->request_event(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                static_cast<vsomeip::event_t>(0x8001),
                its_eventgroups, vsomeip::event_type_e::ET_FIELD,
                vsomeip::reliability_type_e::RT_UNRELIABLE);
        app_->request_event(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                static_cast<vsomeip::event_t>(0x8002),
                its_eventgroups_2, vsomeip::event_type_e::ET_FIELD,
                vsomeip::reliability_type_e::RT_UNRELIABLE);
    }
}

void e2e_test_client::on_availability(vsomeip::service_t _service,
        vsomeip::instance_t _instance, bool _is_available) {

    VSOMEIP_INFO << std::hex << "Client 0x" << app_->get_client()
            << " : Service [" << std::setw(4) << std::setfill('0') << std::hex
            << _service << "." << _instance << "] is "
            << (_is_available ? "available." : "NOT available.");

    // check that correct service / instance ID gets available
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
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            app_->subscribe(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID, 0x01);
            app_->subscribe(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID, 0x02);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            condition_.notify_one();
        }
    }
}

void e2e_test_client::on_message(const std::shared_ptr<vsomeip::message> &_response) {
    VSOMEIP_INFO << "Received a response from Service ["
                 << std::setw(4) << std::setfill('0') << std::hex << _response->get_service()
                 << "."
                 << std::setw(4) << std::setfill('0') << std::hex << _response->get_instance()
                 << "] to Client/Session ["
                 << std::setw(4) << std::setfill('0') << std::hex << _response->get_client()
                 << "/"
                 << std::setw(4) << std::setfill('0') << std::hex << _response->get_session()
                 << "]";
    EXPECT_EQ(vsomeip_test::TEST_SERVICE_SERVICE_ID,  _response->get_service());
    EXPECT_EQ(vsomeip_test::TEST_SERVICE_INSTANCE_ID, _response->get_instance());

    // check fixed payload / CRC in response for service: 1234 method: 8421
    if (_response->get_message_type() == vsomeip::message_type_e::MT_RESPONSE
            && vsomeip_test::TEST_SERVICE_METHOD_ID == _response->get_method()) {
        // check for calculated CRC status OK for the predefined fixed payload sent by service
        VSOMEIP_INFO << "Method ID 0x8421 -> IS_VALID_CRC 8 = " << std::hex << _response->is_valid_crc();
        EXPECT_EQ(true, _response->is_valid_crc());

        // check if payload is as expected as well (including CRC / counter / data ID nibble)
        std::shared_ptr<vsomeip::payload> pl = _response->get_payload();
        uint8_t* dataptr = pl->get_data(); //start after length field
        for(uint32_t i = 0; i< pl->get_length(); i++) {
            EXPECT_EQ(dataptr[i], payloads_profile_01_[received_responses_counters_[vsomeip_test::TEST_SERVICE_METHOD_ID] % vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND][i]);
        }
        received_responses_counters_[vsomeip_test::TEST_SERVICE_METHOD_ID]++;
    } else if (_response->get_message_type() == vsomeip::message_type_e::MT_NOTIFICATION
            && 0x8001 == _response->get_method()) {
        // check CRC / payload calculated by sender for event 0x8001 against expected payload
        // check for calculated CRC status OK for the calculated CRC / payload sent by service
        VSOMEIP_INFO << "Event ID 0x8001 -> IS_VALID_CRC 8 = " << std::hex << _response->is_valid_crc();
        EXPECT_EQ(true, _response->is_valid_crc());

        // check if payload is as expected as well (including CRC / counter / data ID nibble)
        std::shared_ptr<vsomeip::payload> pl = _response->get_payload();
        uint8_t* dataptr = pl->get_data(); //start after length field
        for(uint32_t i = 0; i< pl->get_length(); i++) {
            EXPECT_EQ(dataptr[i], event_payloads_profile_01_[received_responses_counters_[0x8001] % vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND][i]);
        }
        received_responses_counters_[0x8001]++;
    } else if (_response->get_message_type() == vsomeip::message_type_e::MT_RESPONSE
            && 0x6543 == _response->get_method()) {
        // check for calculated CRC status OK for the predefined fixed payload sent by service
        VSOMEIP_INFO << "Method ID 0x6543 -> IS_VALID_CRC 32 = " << std::hex << _response->is_valid_crc();
        EXPECT_EQ(true, _response->is_valid_crc());

        // check if payload is as expected as well (including CRC / counter / data ID nibble)
        std::shared_ptr<vsomeip::payload> pl = _response->get_payload();
        uint8_t* dataptr = pl->get_data(); //start after length field
        for(uint32_t i = 0; i< pl->get_length(); i++) {
            EXPECT_EQ(dataptr[i], payloads_custom_profile_[received_responses_counters_[0x6543] % vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND][i]);
        }
        received_responses_counters_[0x6543]++;
    } else if (_response->get_message_type() == vsomeip::message_type_e::MT_NOTIFICATION
            && 0x8002 == _response->get_method()) {
        VSOMEIP_INFO << "Event ID 0x8002 -> IS_VALID_CRC 32 = " << std::hex << _response->is_valid_crc();
        EXPECT_EQ(true, _response->is_valid_crc());

        // check if payload is as expected as well (including CRC)
        std::shared_ptr<vsomeip::payload> pl = _response->get_payload();
        uint8_t* dataptr = pl->get_data(); //start after length field
        for(uint32_t i = 0; i< pl->get_length(); i++) {
            EXPECT_EQ(dataptr[i], event_payloads_custom_profile_[received_responses_counters_[0x8002] % vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND][i]);
        }
        received_responses_counters_[0x8002]++;
    }

    received_responses_++;
    if (received_responses_ == vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND * 4) {
        VSOMEIP_WARNING << std::hex << app_->get_client()
                << ": Received all messages ~> going down!";
    }
}

void e2e_test_client::run() {
    for (uint32_t i = 0; i < vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND; ++i) {
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

        // send a request which is not e2e protected and expect an
        // protected answer holding a fixed payload (profile 01 CRC8)
        // this call triggers also an event 0x8001 which holds a calculated payload
        request->set_method(vsomeip_test::TEST_SERVICE_METHOD_ID);
        app_->send(request);

        // send a request which is not e2e protected and expect an
        // protected answer holding a fixed payload (custom profile CRC32)
        // this call triggers also an event 0x8002 which holds a calculated payload
        request->set_method(0x6543);
        app_->send(request);

        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    stop();
}

void e2e_test_client::join_sender_thread()
{
    if (sender_.joinable()) {
        sender_.join();
    }
}

void e2e_test_client::shutdown_service() {
    auto request = vsomeip::runtime::get()->create_request(false);
    request->set_service(vsomeip_test::TEST_SERVICE_SERVICE_ID);
    request->set_instance(vsomeip_test::TEST_SERVICE_INSTANCE_ID);
    request->set_method(vsomeip_test::TEST_SERVICE_METHOD_ID_SHUTDOWN);
    app_->send(request);
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    // expect 10 x response messages for both method IDs and events for both Event IDs
    EXPECT_EQ(received_responses_, vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND * 4);
    //EXPECT_EQ(received_allowed_events_, vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND);
}

TEST(someip_e2e_test, basic_subscribe_request_response)
{
    e2e_test_client test_client(is_remote_test, remote_client_allowed);
    if (test_client.init()) {
        test_client.start();
        test_client.join_sender_thread();
    }
}

int main(int argc, char** argv) {

    /*
     e2e profile01 CRC8 protected fixed sample payloads sent by service
     which must be received in client using the following config on client side:
    "service_id" : "0x1234",
    "event_id" : "0x8421",
    "profile" : "CRC8",
    "variant" : "checker",
    "crc_offset" : "0",
    "data_id_mode" : "3",
    "data_length" : "56",
    "data_id" : "0xA73"
     */
    payloads_profile_01_.push_back({{0x82, 0xa4, 0xe3, 0xff, 0xff, 0xff, 0xff, 0xff}}); // initial event
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
     e2e profile01 CRC8 protected payloads which shall be created by e2e module on
     service side using the following config on client side:
    "service_id" : "0x1234",
    "event_id" : "0x8001",
    "profile" : "CRC8",
    "variant" : "checker",
    "crc_offset" : "0",
    "data_id_mode" : "3",
    "data_length" : "56",
    "data_id" : "0xA73"
     */
    event_payloads_profile_01_.push_back({{0xa4, 0xa1, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff}}); // initial event
    event_payloads_profile_01_.push_back({{0x05, 0xa2, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff}});
    event_payloads_profile_01_.push_back({{0x92, 0xa3, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff}});
    event_payloads_profile_01_.push_back({{0x5a, 0xa4, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff}});
    event_payloads_profile_01_.push_back({{0xc8, 0xa5, 0x04, 0xff, 0xff, 0xff, 0xff, 0xff}});
    event_payloads_profile_01_.push_back({{0x69, 0xa6, 0x05, 0xff, 0xff, 0xff, 0xff, 0xff}});
    event_payloads_profile_01_.push_back({{0xfe, 0xa7, 0x06, 0xff, 0xff, 0xff, 0xff, 0xff}});
    event_payloads_profile_01_.push_back({{0xe4, 0xa8, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff}});
    event_payloads_profile_01_.push_back({{0x7c, 0xa9, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff}});
    event_payloads_profile_01_.push_back({{0xdd, 0xaa, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff}});

    /*
     e2e custom profile CRR32 protected fixed sample payloads sent by service
     which must be received in client using the following config on client side:
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

    /*
     e2e custom profile CRC32 protected payloads which shall be created by e2e module on
     service side using the following config on client side for checking:
    "service_id" : "0x1234",
    "event_id" : "0x8002",
    "profile" : "CRC32",
    "variant" : "checker",
    "crc_offset" : "0"
     */
    event_payloads_custom_profile_.push_back({{0x89, 0x0e, 0xbc, 0x80, 0xff, 0xff, 0x00, 0x32}});
    event_payloads_custom_profile_.push_back({{0x90, 0x15, 0x8d, 0xc1, 0xff, 0xff, 0x01, 0x32}});
    event_payloads_custom_profile_.push_back({{0xbb, 0x38, 0xde, 0x02, 0xff, 0xff, 0x02, 0x32}});
    event_payloads_custom_profile_.push_back({{0xa2, 0x23, 0xef, 0x43, 0xff, 0xff, 0x03, 0x32}});
    event_payloads_custom_profile_.push_back({{0xed, 0x62, 0x79, 0x84, 0xff, 0xff, 0x04, 0x32}});
    event_payloads_custom_profile_.push_back({{0xf4, 0x79, 0x48, 0xc5, 0xff, 0xff, 0x05, 0x32}});
    event_payloads_custom_profile_.push_back({{0xdf, 0x54, 0x1b, 0x06, 0xff, 0xff, 0x06, 0x32}});
    event_payloads_custom_profile_.push_back({{0xc6, 0x4f, 0x2a, 0x47, 0xff, 0xff, 0x07, 0x32}});
    event_payloads_custom_profile_.push_back({{0x41, 0xd7, 0x36, 0x88, 0xff, 0xff, 0x08, 0x32}});
    event_payloads_custom_profile_.push_back({{0x58, 0xcc, 0x07, 0xc9, 0xff, 0xff, 0x09, 0x32}});

    received_responses_counters_[vsomeip_test::TEST_SERVICE_METHOD_ID] = 0;
    received_responses_counters_[0x8001] = 0;
    received_responses_counters_[0x6543] = 0;
    received_responses_counters_[0x8002] = 0;

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
