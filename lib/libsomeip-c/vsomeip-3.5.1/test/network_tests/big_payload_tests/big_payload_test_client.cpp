// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "big_payload_test_client.hpp"
#include "big_payload_test_globals.hpp"
#include <common/utility.hpp>

big_payload_test_client::big_payload_test_client(
        bool _use_tcp, big_payload_test::test_mode _test_mode) :
        app_(vsomeip::runtime::get()->create_application("big_payload_test_client")),
        request_(vsomeip::runtime::get()->create_request(_use_tcp)),
        blocked_(false),
        is_available_(false),
        test_mode_(_test_mode),
        number_of_messages_to_send_(
                test_mode_ == big_payload_test::test_mode::RANDOM ?
                        big_payload_test::BIG_PAYLOAD_TEST_NUMBER_MESSAGES_RANDOM :
                        big_payload_test::BIG_PAYLOAD_TEST_NUMBER_MESSAGES),
        number_of_sent_messages_(0),
        number_of_acknowledged_messages_(0),
        sender_(std::bind(&big_payload_test_client::run, this)) {
    switch (test_mode_) {
        case big_payload_test::test_mode::RANDOM:
            service_id_ = big_payload_test::TEST_SERVICE_SERVICE_ID_RANDOM;
            break;
        case big_payload_test::test_mode::LIMITED:
            service_id_ = big_payload_test::TEST_SERVICE_SERVICE_ID_LIMITED;
            break;
        case big_payload_test::test_mode::LIMITED_GENERAL:
            service_id_ = big_payload_test::TEST_SERVICE_SERVICE_ID_LIMITED_GENERAL;
            break;
        case big_payload_test::test_mode::QUEUE_LIMITED_GENERAL:
            service_id_ = big_payload_test::TEST_SERVICE_SERVICE_ID_QUEUE_LIMITED_GENERAL;
            break;
        case big_payload_test::test_mode::QUEUE_LIMITED_SPECIFIC:
            service_id_ = big_payload_test::TEST_SERVICE_SERVICE_ID_QUEUE_LIMITED_SPECIFIC;
            break;
        case big_payload_test::test_mode::UDP:
            service_id_ = big_payload_test::TEST_SERVICE_SERVICE_ID_UDP;
            break;
        default:
            service_id_ = big_payload_test::TEST_SERVICE_SERVICE_ID;
            break;
    }
}

bool big_payload_test_client::init()
{
    if (!app_->init()) {
        ADD_FAILURE() << "Couldn't initialize application";
        return false;
    }

    app_->register_state_handler(
            std::bind(&big_payload_test_client::on_state, this,
                    std::placeholders::_1));

    app_->register_message_handler(vsomeip::ANY_SERVICE,
            vsomeip::ANY_INSTANCE, vsomeip::ANY_METHOD,
            std::bind(&big_payload_test_client::on_message, this,
                    std::placeholders::_1));

    app_->register_availability_handler(service_id_,
            big_payload_test::TEST_SERVICE_INSTANCE_ID,
            std::bind(&big_payload_test_client::on_availability, this,
                    std::placeholders::_1, std::placeholders::_2,
                    std::placeholders::_3));
    return true;
}

void big_payload_test_client::start()
{
    VSOMEIP_INFO << "Starting Client...";
    app_->start();
}

void big_payload_test_client::stop()
{
    VSOMEIP_INFO << "Stopping Client...";
    if (test_mode_ == big_payload_test::test_mode::LIMITED
            || test_mode_ == big_payload_test::test_mode::LIMITED_GENERAL
            || test_mode_ == big_payload_test::test_mode::QUEUE_LIMITED_GENERAL
            || test_mode_ == big_payload_test::test_mode::QUEUE_LIMITED_SPECIFIC) {
        std::this_thread::sleep_for(std::chrono::milliseconds(3000));
        EXPECT_EQ(number_of_acknowledged_messages_, number_of_messages_to_send_ / 4);
    } else if (test_mode_ == big_payload_test::test_mode::UDP) {
        std::this_thread::sleep_for(std::chrono::milliseconds(3000));
        EXPECT_EQ(number_of_acknowledged_messages_, number_of_messages_to_send_);
    }
    app_->clear_all_handler();
    app_->stop();
}

void big_payload_test_client::join_sender_thread(){
    sender_.join();
    if (test_mode_ == big_payload_test::test_mode::LIMITED
            || test_mode_ == big_payload_test::test_mode::LIMITED_GENERAL
            || test_mode_ == big_payload_test::test_mode::QUEUE_LIMITED_GENERAL
            || test_mode_ == big_payload_test::test_mode::QUEUE_LIMITED_SPECIFIC) {
        EXPECT_EQ(number_of_acknowledged_messages_, number_of_messages_to_send_ / 4);
    } else if (test_mode_ == big_payload_test::test_mode::UDP) {
        EXPECT_EQ(number_of_sent_messages_, number_of_acknowledged_messages_);
    } else {
        EXPECT_EQ(number_of_sent_messages_, number_of_acknowledged_messages_);
    }
}

void big_payload_test_client::on_state(vsomeip::state_type_e _state)
{
    if (_state == vsomeip::state_type_e::ST_REGISTERED) {
        app_->request_service(service_id_,
                big_payload_test::TEST_SERVICE_INSTANCE_ID, false);
    }
}

void big_payload_test_client::on_availability(vsomeip::service_t _service,
        vsomeip::instance_t _instance, bool _is_available)
{
    VSOMEIP_INFO << "Service [" << std::setw(4) << std::setfill('0') << std::hex
            << _service << "." << _instance << "] is "
            << (_is_available ? "available." : "NOT available.");

    if(service_id_ == _service
            && big_payload_test::TEST_SERVICE_INSTANCE_ID == _instance)
    {
        if(is_available_ && !_is_available)
        {
            is_available_ = false;
        }
        else if(_is_available && !is_available_)
        {
            is_available_ = true;
            send();
        }
    }
}

void big_payload_test_client::on_message(const std::shared_ptr<vsomeip::message>& _response)
{
    VSOMEIP_INFO << "Received a response from Service [" << std::setw(4)
            << std::setfill('0') << std::hex << _response->get_service() << "."
            << std::setw(4) << std::setfill('0') << std::hex
            << _response->get_instance() << "] to Client/Session ["
            << std::setw(4) << std::setfill('0') << std::hex
            << _response->get_client() << "/" << std::setw(4)
            << std::setfill('0') << std::hex << _response->get_session()
            << "] size: " << std::dec << _response->get_payload()->get_length();
    static vsomeip::session_t last_session(0);
    ASSERT_GT(_response->get_session(), last_session);
    last_session = _response->get_session();

    if(test_mode_ == big_payload_test::test_mode::RANDOM) {
        ASSERT_LT(_response->get_payload()->get_length(), big_payload_test::BIG_PAYLOAD_SIZE_RANDOM);
    } else if (test_mode_ == big_payload_test::test_mode::UDP) {
        EXPECT_EQ(big_payload_test::BIG_PAYLOAD_SIZE_UDP, _response->get_payload()->get_length());
    } else {
        ASSERT_EQ(_response->get_payload()->get_length(), big_payload_test::BIG_PAYLOAD_SIZE);
    }

    bool check(true);
    vsomeip::length_t len = _response->get_payload()->get_length();
    vsomeip::byte_t* datap = _response->get_payload()->get_data();
    for(unsigned int i = 0; i < len; ++i) {
        check = check && datap[i] == big_payload_test::DATA_SERVICE_TO_CLIENT;
    }
    if(!check) {
        GTEST_FATAL_FAILURE_("wrong data transmitted");
    }
    number_of_acknowledged_messages_++;
    if (test_mode_ == big_payload_test::test_mode::LIMITED
            || test_mode_ == big_payload_test::test_mode::LIMITED_GENERAL
            || test_mode_ == big_payload_test::test_mode::QUEUE_LIMITED_GENERAL
            || test_mode_ == big_payload_test::test_mode::QUEUE_LIMITED_SPECIFIC) {
        if (number_of_acknowledged_messages_ == number_of_messages_to_send_ / 4) {
            send();
        }
    } else if ( number_of_acknowledged_messages_ == number_of_messages_to_send_) {
        send();
    }
}

void big_payload_test_client::send()
{
    std::lock_guard<std::mutex> its_lock(mutex_);
    blocked_ = true;
    condition_.notify_one();
}

void big_payload_test_client::run()
{
    std::unique_lock<std::mutex> its_lock(mutex_);
    while (!blocked_)
    {
        condition_.wait(its_lock);
    }
    blocked_ = false;

    request_->set_service(service_id_);
    request_->set_instance(big_payload_test::TEST_SERVICE_INSTANCE_ID);
    request_->set_method(big_payload_test::TEST_SERVICE_METHOD_ID);

    std::srand(static_cast<unsigned int>(std::time(0)));

    std::shared_ptr<vsomeip::payload> its_payload =
            vsomeip::runtime::get()->create_payload();
    std::vector<vsomeip::byte_t> its_payload_data;

    for (unsigned int i = 0; i < number_of_messages_to_send_; i++)
    {
        if (test_mode_ == big_payload_test::test_mode::RANDOM) {
            unsigned int datasize(static_cast<unsigned int>(std::rand()) % big_payload_test::BIG_PAYLOAD_SIZE_RANDOM);
            its_payload_data.assign(datasize, big_payload_test::DATA_CLIENT_TO_SERVICE);
        } else if (test_mode_ == big_payload_test::test_mode::LIMITED
                || test_mode_ == big_payload_test::test_mode::LIMITED_GENERAL
                || test_mode_ == big_payload_test::test_mode::QUEUE_LIMITED_GENERAL
                || test_mode_ == big_payload_test::test_mode::QUEUE_LIMITED_SPECIFIC) {
            if (i % 2) {
                // try to sent a too big payload for half of the messages
                its_payload_data.assign(big_payload_test::BIG_PAYLOAD_SIZE + 1,
                        big_payload_test::DATA_CLIENT_TO_SERVICE);
            } else {
                its_payload_data.assign(big_payload_test::BIG_PAYLOAD_SIZE,
                        big_payload_test::DATA_CLIENT_TO_SERVICE);
            }
        } else if (test_mode_ == big_payload_test::test_mode::UDP) {
            its_payload_data.assign(big_payload_test::BIG_PAYLOAD_SIZE_UDP,
                    big_payload_test::DATA_CLIENT_TO_SERVICE);
        } else {
            its_payload_data.assign(big_payload_test::BIG_PAYLOAD_SIZE,
                    big_payload_test::DATA_CLIENT_TO_SERVICE);
        }
        its_payload->set_data(its_payload_data);
        request_->set_payload(its_payload);
        VSOMEIP_INFO << "Client/Session [" << std::setw(4) << std::setfill('0') << std::hex
                     << request_->get_client() << "/" << std::setw(4) << std::setfill('0')
                     << std::hex << request_->get_session()
                     << "] is going to send a request to Service [" << std::setw(4)
                     << std::setfill('0') << std::hex << request_->get_service() << "."
                     << std::setw(4) << std::setfill('0') << std::hex << request_->get_instance()
                     << "] size: " << std::dec << request_->get_payload()->get_length()
                     << ". Sent Messages: " << number_of_sent_messages_ + 1;
        app_->send(request_);
        if (test_mode_ == big_payload_test::test_mode::QUEUE_LIMITED_GENERAL
            || test_mode_ == big_payload_test::test_mode::QUEUE_LIMITED_SPECIFIC) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
        number_of_sent_messages_++;
    }
    while(!blocked_) {
        if (std::cv_status::timeout
                == condition_.wait_for(its_lock, std::chrono::seconds(120))) {
            GTEST_FATAL_FAILURE_("Didn't receive all replies within time");
        } else {
            if (test_mode_ == big_payload_test::LIMITED
                    || test_mode_ == big_payload_test::test_mode::LIMITED_GENERAL
                    || test_mode_ == big_payload_test::test_mode::QUEUE_LIMITED_GENERAL
                    || test_mode_ == big_payload_test::test_mode::QUEUE_LIMITED_SPECIFIC) {
                EXPECT_EQ(number_of_messages_to_send_ / 4,
                        number_of_acknowledged_messages_);
            } else {
                EXPECT_EQ(number_of_sent_messages_,
                        number_of_acknowledged_messages_);
            }
        }
    }
    stop();
}

static big_payload_test::test_mode test_mode(big_payload_test::test_mode::UNKNOWN);

TEST(someip_big_payload_test, send_ten_messages_to_service)
{
    bool use_tcp = (test_mode != big_payload_test::test_mode::UDP);
    big_payload_test_client test_client_(use_tcp, test_mode);
    if (test_client_.init()) {
        test_client_.start();
        test_client_.join_sender_thread();
    }
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    if (argc > 1) {
        if (std::string("RANDOM") == std::string(argv[1])) {
            test_mode = big_payload_test::test_mode::RANDOM;
        } else if (std::string("LIMITED") == std::string(argv[1])) {
            test_mode = big_payload_test::test_mode::LIMITED;
        } else if (std::string("LIMITEDGENERAL") == std::string(argv[1])) {
            test_mode = big_payload_test::test_mode::LIMITED_GENERAL;
        } else if (std::string("QUEUELIMITEDGENERAL") == std::string(argv[1])) {
            test_mode = big_payload_test::test_mode::QUEUE_LIMITED_GENERAL;
        } else if (std::string("QUEUELIMITEDSPECIFIC") == std::string(argv[1])) {
            test_mode = big_payload_test::test_mode::QUEUE_LIMITED_SPECIFIC;
        } else if (std::string("UDP") == std::string(argv[1])) {
            test_mode = big_payload_test::test_mode::UDP;
        }
    }
    return RUN_ALL_TESTS();
}
#endif
