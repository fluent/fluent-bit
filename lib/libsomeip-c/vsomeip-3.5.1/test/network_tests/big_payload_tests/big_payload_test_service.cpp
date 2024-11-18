// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include "big_payload_test_service.hpp"

#include "big_payload_test_globals.hpp"

big_payload_test_service::big_payload_test_service(big_payload_test::test_mode _test_mode) :
                app_(vsomeip::runtime::get()->create_application("big_payload_test_service")),
                is_registered_(false),
                blocked_(false),
                test_mode_(_test_mode),
                number_of_received_messages_(0),
                offer_thread_(std::bind(&big_payload_test_service::run, this))
{
    switch (test_mode_) {
        case big_payload_test::test_mode::RANDOM:
            expected_messages_ = big_payload_test::BIG_PAYLOAD_TEST_NUMBER_MESSAGES_RANDOM;
            service_id_ = big_payload_test::TEST_SERVICE_SERVICE_ID_RANDOM;
            break;
        case big_payload_test::test_mode::LIMITED:
            expected_messages_ = big_payload_test::BIG_PAYLOAD_TEST_NUMBER_MESSAGES / 2;
            service_id_ = big_payload_test::TEST_SERVICE_SERVICE_ID_LIMITED;
            break;
        case big_payload_test::test_mode::LIMITED_GENERAL:
            expected_messages_ = big_payload_test::BIG_PAYLOAD_TEST_NUMBER_MESSAGES / 2;
            service_id_ = big_payload_test::TEST_SERVICE_SERVICE_ID_LIMITED_GENERAL;
            break;
        case big_payload_test::test_mode::QUEUE_LIMITED_GENERAL:
            expected_messages_ = big_payload_test::BIG_PAYLOAD_TEST_NUMBER_MESSAGES / 2;
            service_id_ = big_payload_test::TEST_SERVICE_SERVICE_ID_QUEUE_LIMITED_GENERAL;
            break;
        case big_payload_test::test_mode::QUEUE_LIMITED_SPECIFIC:
            expected_messages_ = big_payload_test::BIG_PAYLOAD_TEST_NUMBER_MESSAGES / 2;
            service_id_ = big_payload_test::TEST_SERVICE_SERVICE_ID_QUEUE_LIMITED_SPECIFIC;
            break;
        case big_payload_test::test_mode::UDP:
            expected_messages_ = big_payload_test::BIG_PAYLOAD_TEST_NUMBER_MESSAGES;
            service_id_ = big_payload_test::TEST_SERVICE_SERVICE_ID_UDP;
            break;
        default:
            expected_messages_ = big_payload_test::BIG_PAYLOAD_TEST_NUMBER_MESSAGES;
            service_id_ = big_payload_test::TEST_SERVICE_SERVICE_ID;
            break;
    }
}

bool big_payload_test_service::init()
{
    std::lock_guard<std::mutex> its_lock(mutex_);
    std::srand(static_cast<unsigned int>(std::time(0)));
    if (!app_->init()) {
        ADD_FAILURE() << "Couldn't initialize application";
        return false;
    }
    app_->register_message_handler(vsomeip::ANY_SERVICE,
            big_payload_test::TEST_SERVICE_INSTANCE_ID,
            big_payload_test::TEST_SERVICE_METHOD_ID,
            std::bind(&big_payload_test_service::on_message, this,
                    std::placeholders::_1));

    app_->register_state_handler(
            std::bind(&big_payload_test_service::on_state, this,
                    std::placeholders::_1));
    return true;
}

void big_payload_test_service::start()
{
    VSOMEIP_INFO << "Starting Service...";
    app_->start();
}

void big_payload_test_service::stop()
{
    VSOMEIP_INFO << "Stopping Service...";
    stop_offer();
    app_->clear_all_handler();
    app_->stop();
}

void big_payload_test_service::join_offer_thread()
{
    offer_thread_.join();
}

void big_payload_test_service::detach_offer_thread()
{
    offer_thread_.detach();
}

void big_payload_test_service::offer() {
    app_->offer_service(service_id_,
            big_payload_test::TEST_SERVICE_INSTANCE_ID);
}

void big_payload_test_service::stop_offer() {
    app_->stop_offer_service(service_id_,
            big_payload_test::TEST_SERVICE_INSTANCE_ID);
}

void big_payload_test_service::on_state(vsomeip::state_type_e _state)
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

void big_payload_test_service::on_message(const std::shared_ptr<vsomeip::message>& _request)
{
    VSOMEIP_INFO << "Received a message with Client/Session [" << std::setw(4)
            << std::setfill('0') << std::hex << _request->get_client() << "/"
            << std::setw(4) << std::setfill('0') << std::hex
            << _request->get_session() << "] size: " << std::dec
            << _request->get_payload()->get_length();
    {
        std::lock_guard<std::mutex> its_lock(mutex_);
        incoming_requests_.push(_request);
        condition_.notify_one();
    }


}

void big_payload_test_service::run()
{
    {
        std::unique_lock<std::mutex> its_lock(mutex_);
        while (!blocked_) {
            condition_.wait(its_lock);
        }

        offer();

        // wait for shutdown
        blocked_ = false;
        while (!blocked_ || !incoming_requests_.empty()) {
            if (incoming_requests_.empty()) {
                condition_.wait(its_lock);
            }
            auto _request = incoming_requests_.front();
            incoming_requests_.pop();
            number_of_received_messages_++;
            its_lock.unlock();

            static vsomeip::session_t last_session(0);
            ASSERT_GT(_request->get_session(), last_session);
            last_session = _request->get_session();
            if (test_mode_ == big_payload_test::test_mode::RANDOM) {
                EXPECT_LT(_request->get_payload()->get_length(), big_payload_test::BIG_PAYLOAD_SIZE_RANDOM);
            } else if (test_mode_ == big_payload_test::test_mode::UDP) {
                EXPECT_EQ(big_payload_test::BIG_PAYLOAD_SIZE_UDP, _request->get_payload()->get_length());
            } else {
                EXPECT_EQ(big_payload_test::BIG_PAYLOAD_SIZE, _request->get_payload()->get_length());
            }
            bool check(true);
            vsomeip::length_t len = _request->get_payload()->get_length();
            vsomeip::byte_t* datap = _request->get_payload()->get_data();
            for(unsigned int i = 0; i < len; ++i) {
                check = check && datap[i] == big_payload_test::DATA_CLIENT_TO_SERVICE;
            }
            if(!check) {
                GTEST_FATAL_FAILURE_("wrong data transmitted");
            }

            // send response
            std::shared_ptr<vsomeip::message> its_response =
                    vsomeip::runtime::get()->create_response(_request);

            std::shared_ptr<vsomeip::payload> its_payload = vsomeip::runtime::get()
            ->create_payload();
            std::vector<vsomeip::byte_t> its_payload_data;
            if (test_mode_ == big_payload_test::test_mode::RANDOM) {
                its_payload_data.assign(static_cast<unsigned int>(std::rand()) % big_payload_test::BIG_PAYLOAD_SIZE_RANDOM,
                        big_payload_test::DATA_SERVICE_TO_CLIENT);
            } else if (test_mode_ == big_payload_test::test_mode::LIMITED
                    || test_mode_ == big_payload_test::test_mode::LIMITED_GENERAL
                    || test_mode_ == big_payload_test::test_mode::QUEUE_LIMITED_GENERAL
                    || test_mode_ == big_payload_test::test_mode::QUEUE_LIMITED_SPECIFIC) {
                if (number_of_received_messages_ % 2) {
                    // try to send to big response for half of the received messsages.
                    // this way the client will only get replies for a fourth of his sent
                    // requests as he tries to sent to big data for every second request
                    // as well
                    its_payload_data.assign(big_payload_test::BIG_PAYLOAD_SIZE + 1,
                            big_payload_test::DATA_SERVICE_TO_CLIENT);
                } else {
                    its_payload_data.assign(big_payload_test::BIG_PAYLOAD_SIZE,
                            big_payload_test::DATA_SERVICE_TO_CLIENT);
                }
            } else if (test_mode_ == big_payload_test::test_mode::UDP) {
                its_payload_data.assign(big_payload_test::BIG_PAYLOAD_SIZE_UDP,
                        big_payload_test::DATA_SERVICE_TO_CLIENT);
            } else {
                its_payload_data.assign(big_payload_test::BIG_PAYLOAD_SIZE,
                        big_payload_test::DATA_SERVICE_TO_CLIENT);
            }

            its_payload->set_data(its_payload_data);
            its_response->set_payload(its_payload);

            app_->send(its_response);

            if(number_of_received_messages_ == expected_messages_) {
                ASSERT_EQ(expected_messages_, number_of_received_messages_);
                blocked_ = true;
            }
            its_lock.lock();
        }
    }
    std::this_thread::sleep_for(std::chrono::seconds(3));
    if (test_mode_ == big_payload_test::test_mode::LIMITED
            || test_mode_ == big_payload_test::test_mode::LIMITED_GENERAL
            || test_mode_ == big_payload_test::test_mode::QUEUE_LIMITED_GENERAL
            || test_mode_ == big_payload_test::test_mode::QUEUE_LIMITED_SPECIFIC
            || test_mode_ == big_payload_test::test_mode::UDP) {
        EXPECT_EQ(expected_messages_, number_of_received_messages_);
    }
    stop();
}

static big_payload_test::test_mode test_mode(big_payload_test::test_mode::UNKNOWN);


TEST(someip_big_payload_test, receive_ten_messages_and_send_reply)
{
    big_payload_test_service test_service(test_mode);
    if (test_service.init()) {
        test_service.start();
        test_service.join_offer_thread();
    } else {
        test_service.detach_offer_thread();
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
