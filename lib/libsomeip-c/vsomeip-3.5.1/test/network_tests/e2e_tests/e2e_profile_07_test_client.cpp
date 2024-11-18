// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include "e2e_profile_07_test_common.hpp"
#include "e2e_profile_07_test_client.hpp"

#include <vsomeip/internal/logger.hpp>

std::vector<std::vector<vsomeip::byte_t>> responses_;
std::vector<std::vector<vsomeip::byte_t>> events_;

std::map<vsomeip::method_t, uint32_t> counters_;


e2e_profile_07_test_client::e2e_profile_07_test_client()
    : app_(vsomeip::runtime::get()->create_application()),
      is_available_(false),
      sender_(std::bind(&e2e_profile_07_test_client::run, this)),
      received_(0) {

}

bool
e2e_profile_07_test_client::init() {

    if (!app_->init()) {
        ADD_FAILURE() << __func__ << ": Cannot initialize application";
        return false;
    }

    app_->register_state_handler(
            std::bind(&e2e_profile_07_test_client::on_state, this,
                    std::placeholders::_1));

    app_->register_message_handler(
            PROFILE_07_SERVICE, PROFILE_07_INSTANCE, vsomeip::ANY_METHOD,
            std::bind(&e2e_profile_07_test_client::on_message, this,
                    std::placeholders::_1));

    app_->register_availability_handler(
            PROFILE_07_SERVICE, PROFILE_07_INSTANCE,
            std::bind(&e2e_profile_07_test_client::on_availability, this,
                    std::placeholders::_1, std::placeholders::_2,
                    std::placeholders::_3));

    return true;
}

void
e2e_profile_07_test_client::start() {

    VSOMEIP_INFO << __func__ << ": Starting...";
    app_->start();
}

void
e2e_profile_07_test_client::stop() {

    VSOMEIP_INFO << __func__ << ": Stopping...";
    shutdown_service();
    app_->clear_all_handler();
    app_->stop();
}

void
e2e_profile_07_test_client::on_state(vsomeip::state_type_e _state) {

    if (_state == vsomeip::state_type_e::ST_REGISTERED) {
        app_->request_service(PROFILE_07_SERVICE, PROFILE_07_INSTANCE);

        // request event 0x8001, that is protected by E2E Profile 07
        app_->request_event(PROFILE_07_SERVICE, PROFILE_07_INSTANCE,
                PROFILE_07_EVENT, { PROFILE_07_EVENTGROUP },
                vsomeip::event_type_e::ET_FIELD,
                vsomeip::reliability_type_e::RT_UNRELIABLE);
    }
}

void
e2e_profile_07_test_client::on_availability(
        vsomeip::service_t _service, vsomeip::instance_t _instance,
        bool _is_available) {

    VSOMEIP_INFO << __func__ << ": Client "
            << std::hex << std::setw(4) << std::setfill('0')
            << app_->get_client()
            << " : Service [" << _service << "." << _instance
            << "] is " << (_is_available ? "available." : "NOT available.");

    // check that correct service / instance ID gets available
    if (_is_available) {
        EXPECT_EQ(PROFILE_07_SERVICE, _service);
        EXPECT_EQ(PROFILE_07_INSTANCE, _instance);
    }

    if (PROFILE_07_SERVICE == _service  && PROFILE_07_INSTANCE == _instance) {
        std::unique_lock<std::mutex> its_lock(mutex_);
        if (is_available_ != !_is_available) {
            is_available_ = false;
        } else if(_is_available && !is_available_) {
            is_available_ = true;

            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            app_->subscribe(PROFILE_07_SERVICE, PROFILE_07_INSTANCE,
                    PROFILE_07_EVENTGROUP, PROFILE_07_MAJOR);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            condition_.notify_one();
        }
    }
}

void
e2e_profile_07_test_client::on_message(const std::shared_ptr<vsomeip::message> &_message) {

    VSOMEIP_INFO << __func__ << ": Received a message from Service ["
            << std::setw(4) << std::setfill('0') << std::hex
            << _message->get_service() << "." << _message->get_instance()
            << "] to Client/Session ["
            << _message->get_client() << "/" << _message->get_session()
            << "]";

    EXPECT_EQ(PROFILE_07_SERVICE, _message->get_service());
    EXPECT_EQ(PROFILE_07_INSTANCE, _message->get_instance());

    // check fixed payload / CRC in response for service: d025 method: 0001
    if (vsomeip::message_type_e::MT_RESPONSE == _message->get_message_type()
            && PROFILE_07_METHOD == _message->get_method()) {
        // check for calculated CRC status OK for the predefined fixed payload sent by service
        VSOMEIP_INFO << "Method ID 0x0001 -> IS_VALID_CRC = "
                << std::boolalpha << _message->is_valid_crc();
        EXPECT_EQ(true, _message->is_valid_crc());

        // check if payload is as expected as well (including CRC / counter / data ID)
        std::shared_ptr<vsomeip::payload> its_payload = _message->get_payload();
        const auto its_data = its_payload->get_data();
        for (size_t i = 0; i < its_payload->get_length(); i++)
            EXPECT_EQ(its_data[i], responses_[counters_[PROFILE_07_METHOD]
                                              % PROFILE_07_NUM_MESSAGES][i]);

        counters_[PROFILE_07_METHOD]++;

    } else if (vsomeip::message_type_e::MT_NOTIFICATION == _message->get_message_type()
            && PROFILE_07_EVENT == _message->get_method()) {

        // check CRC / payload calculated by sender for event 0x8001 against expected payload
        // check for calculated CRC status OK for the calculated CRC / payload sent by service
        VSOMEIP_INFO << __func__ << ": Event 0x8001 -> IS_VALID_CRC = "
                << std::boolalpha << _message->is_valid_crc();
        EXPECT_EQ(true, _message->is_valid_crc());

        // check if payload is as expected as well (including CRC / counter / data ID nibble)
        std::shared_ptr<vsomeip::payload> its_payload = _message->get_payload();
        const auto its_data = its_payload->get_data();
        for (size_t i = 0; i< its_payload->get_length(); i++)
            EXPECT_EQ(its_data[i], events_[counters_[PROFILE_07_EVENT]
                                           % PROFILE_07_NUM_MESSAGES][i]);

        counters_[PROFILE_07_EVENT]++;
    }

    received_++;
    if (received_ == PROFILE_07_NUM_MESSAGES * 2) {
        VSOMEIP_WARNING << __func__ << ": Client"
                << std::setw(4) << std::setfill('0') << std::hex
                << app_->get_client()
                << " received all messages ~> going down!";
    }
}

void
e2e_profile_07_test_client::run() {

    for (int i = 0; i < PROFILE_07_NUM_MESSAGES; ++i) {
        {
            std::unique_lock<std::mutex> its_lock(mutex_);
            while (!is_available_) {
                condition_.wait(its_lock);
            }
        }

        auto request = vsomeip::runtime::get()->create_request(false);
        request->set_service(PROFILE_07_SERVICE);
        request->set_instance(PROFILE_07_INSTANCE);
        request->set_interface_version(PROFILE_07_MAJOR);

        // send a request which is not e2e protected and expect an
        // protected answer holding a fixed payload (E2E Profile 07)
        // this call triggers also an event 0x8001 which holds a
        // calculated payload
        request->set_method(PROFILE_07_METHOD);

        app_->send(request);

        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    stop();
}

void
e2e_profile_07_test_client::join_sender_thread() {

    if (sender_.joinable()) {
        sender_.join();
    }
}

void
e2e_profile_07_test_client::shutdown_service() {

    auto request = vsomeip::runtime::get()->create_request(false);
    request->set_service(PROFILE_07_SERVICE);
    request->set_instance(PROFILE_07_INSTANCE);
    request->set_method(PROFILE_07_SHUTDOWN);
    request->set_interface_version(PROFILE_07_MAJOR);

    app_->send(request);

    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    // expect 10 responses + 10 events
    EXPECT_EQ(received_, PROFILE_07_NUM_MESSAGES * 2);
}

TEST(someip_e2e_profile_07_test, test_crc_calculation) {

    e2e_profile_07_test_client test_client;

    if (test_client.init()) {
        test_client.start();
        test_client.join_sender_thread();
    }
}

int main(int argc, char** argv) {

    // The first 8 bytes are the CRC calculated over all the data (except the CRC itself) and the previous 8 bytes from the vSomeIP header
    // The next 4 bytes are the length of the data
    // The next 4 bytes are the counter, starting at 0
    // the next 4 bytes are the DataID
    // The rest are just random for the test
    // {
    //     CRC,
    //     Length, Counter,
    //     DataID, Random Data,
    //     Random Data
    // }

    responses_ = {
        {
            0xf7, 0xa1, 0x9e, 0x0e, 0x9d, 0xbd, 0xa7, 0xca,
            0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x2d, 0x00, 0x01, 0x06, 0xfe,
            0x01, 0x3e, 0x4c, 0xcc, 0xcd, 0x80, 0x3f, 0xb2,
            0x3d, 0x83, 0x3e, 0xba, 0x68, 0xed, 0x3f, 0xb3,
            0x7a, 0xf2, 0xbd, 0x96, 0xc1, 0x42, 0x3d, 0x25,
            0x1a, 0x62, 0xbd, 0xae, 0x77, 0xf3, 0x3f, 0x80,
            0x00, 0x00, 0xfc, 0x01, 0x01, 0x3c, 0x1d, 0xbd,
            0x4e, 0x01, 0x01, 0x3c, 0x2b, 0x87, 0xed, 0x00
        },
        {
            0xca, 0xb7, 0xae, 0x78, 0xe2, 0xa5, 0xdc, 0xab,
            0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x2d, 0x00, 0x01, 0x06, 0xfe,
            0x01, 0x3e, 0x4c, 0xcc, 0xcd, 0x80, 0x3f, 0xb2,
            0x3c, 0x2f, 0x3e, 0xba, 0x46, 0x81, 0x3f, 0xb3,
            0x73, 0x8d, 0xbd, 0x93, 0xcb, 0xae, 0x3c, 0xf7,
            0xd2, 0x58, 0xbd, 0xa2, 0x6e, 0xcd, 0x3f, 0x80,
            0x00, 0x00, 0xfc, 0x01, 0x01, 0x3c, 0x1c, 0x89,
            0x24, 0x01, 0x01, 0x3c, 0x2b, 0x24, 0x45, 0x00
        },
        {
            0xbe, 0x5c, 0xe8, 0xd0, 0xa8, 0x3a, 0xca, 0x41,
            0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x2d, 0x00, 0x01, 0x06, 0xfe,
            0x01, 0x3e, 0x4c, 0xcc, 0xcd, 0x80, 0x3f, 0xb2,
            0x3e, 0xf3, 0x3e, 0xba, 0x97, 0x45, 0x3f, 0xb3,
            0x86, 0x81, 0xbd, 0x8a, 0xda, 0xc2, 0x3c, 0xf6,
            0x00, 0x7a, 0xbd, 0xb4, 0xf9, 0xb9, 0x3f, 0x80,
            0x00, 0x00, 0xfc, 0x01, 0x01, 0x3c, 0x1c, 0x1b,
            0x72, 0x01, 0x01, 0x3c, 0x2a, 0x9e, 0x1f, 0x00
        }
    };

    events_ = {
        {
            0x23, 0xfc, 0x1f, 0x7f, 0x13, 0x58, 0x95, 0xc0,
            0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x2d, 0x00, 0x01, 0x06, 0xfe,
            0x01, 0x3e, 0x4c, 0xcc, 0xcd, 0x80, 0x3f, 0xb2,
            0x3d, 0x83, 0x3e, 0xba, 0x68, 0xed, 0x3f, 0xb3,
            0x7a, 0xf2, 0xbd, 0x96, 0xc1, 0x42, 0x3d, 0x25,
            0x1a, 0x62, 0xbd, 0xae, 0x77, 0xf3, 0x3f, 0x80,
            0x00, 0x00, 0xfc, 0x01, 0x01, 0x3c, 0x1d, 0xbd,
            0x4e, 0x01, 0x01, 0x3c, 0x2b, 0x87, 0xed, 0x00
        },
        {
            0xd0, 0x18, 0xa8, 0x8d, 0x18, 0xcf, 0x43, 0x6e,
            0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x2d, 0x00, 0x01, 0x06, 0xfe,
            0x01, 0x3e, 0x4c, 0xcc, 0xcd, 0x80, 0x3f, 0xb2,
            0x3c, 0x2f, 0x3e, 0xba, 0x46, 0x81, 0x3f, 0xb3,
            0x73, 0x8d, 0xbd, 0x93, 0xcb, 0xae, 0x3c, 0xf7,
            0xd2, 0x58, 0xbd, 0xa2, 0x6e, 0xcd, 0x3f, 0x80,
            0x00, 0x00, 0xfc, 0x01, 0x01, 0x3c, 0x1c, 0x89,
            0x24, 0x01, 0x01, 0x3c, 0x2b, 0x24, 0x45, 0x00
        },
        {
            0xe1, 0x5d, 0x93, 0x59, 0x7e, 0x2a, 0xce, 0xc1,
            0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x2d, 0x00, 0x01, 0x06, 0xfe,
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
