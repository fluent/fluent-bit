// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include "header_factory_test_client.hpp"

header_factory_test_client::header_factory_test_client(bool _use_tcp) :
                app_(vsomeip::runtime::get()->create_application()),
                request_(vsomeip::runtime::get()->create_request(_use_tcp)),
                blocked_(false),
                is_available_(false),
                number_of_messages_to_send_(vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND),
                number_of_sent_messages_(0),
                number_of_acknowledged_messages_(0),
                sender_(std::bind(&header_factory_test_client::run, this))
{
}

bool header_factory_test_client::init()
{
    if (!app_->init()) {
        ADD_FAILURE() << "Couldn't initialize application";
        return false;
    }

    app_->register_state_handler(
            std::bind(&header_factory_test_client::on_state, this,
                    std::placeholders::_1));

    app_->register_message_handler(vsomeip::ANY_SERVICE,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID, vsomeip::ANY_METHOD,
            std::bind(&header_factory_test_client::on_message, this,
                    std::placeholders::_1));

    app_->register_availability_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID,
            std::bind(&header_factory_test_client::on_availability, this,
                    std::placeholders::_1, std::placeholders::_2,
                    std::placeholders::_3));
    return true;
}

void header_factory_test_client::start()
{
    VSOMEIP_INFO << "Starting...";
    app_->start();
}

void header_factory_test_client::stop()
{
    VSOMEIP_INFO << "Stopping...";
    app_->clear_all_handler();
    app_->stop();
}

void header_factory_test_client::join_sender_thread(){
    sender_.join();

    ASSERT_EQ(number_of_sent_messages_, number_of_acknowledged_messages_);
}

void header_factory_test_client::on_state(vsomeip::state_type_e _state)
{
    if(_state == vsomeip::state_type_e::ST_REGISTERED)
    {
        app_->request_service(vsomeip_test::TEST_SERVICE_SERVICE_ID,
                vsomeip_test::TEST_SERVICE_INSTANCE_ID, false);
    }
}

void header_factory_test_client::on_availability(vsomeip::service_t _service,
        vsomeip::instance_t _instance, bool _is_available)
{
    VSOMEIP_INFO << "Service [" << std::setw(4) << std::setfill('0') << std::hex
            << _service << "." << _instance << "] is "
            << (_is_available ? "available." : "NOT available.");

    if(vsomeip_test::TEST_SERVICE_SERVICE_ID == _service
            && vsomeip_test::TEST_SERVICE_INSTANCE_ID == _instance)
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

void header_factory_test_client::on_message(const std::shared_ptr<vsomeip::message>& _response)
{
    VSOMEIP_INFO << "Received a response from Service [" << std::setw(4)
            << std::setfill('0') << std::hex << _response->get_service() << "."
            << std::setw(4) << std::setfill('0') << std::hex
            << _response->get_instance() << "] to Client/Session ["
            << std::setw(4) << std::setfill('0') << std::hex
            << _response->get_client() << "/" << std::setw(4)
            << std::setfill('0') << std::hex << _response->get_session() << "]";
    number_of_acknowledged_messages_++;
    ASSERT_EQ(_response->get_service(), vsomeip_test::TEST_SERVICE_SERVICE_ID);
    ASSERT_EQ(_response->get_instance(), vsomeip_test::TEST_SERVICE_INSTANCE_ID);
    ASSERT_EQ(_response->get_session(),
            static_cast<vsomeip::session_t>(number_of_acknowledged_messages_));
    if(number_of_acknowledged_messages_ == number_of_messages_to_send_) {
        std::lock_guard<std::mutex> its_lock(mutex_);
        blocked_ = true;
        condition_.notify_one();
    }
}

void header_factory_test_client::send()
{
    std::lock_guard<std::mutex> its_lock(mutex_);
    blocked_ = true;
    condition_.notify_one();
}

void header_factory_test_client::run()
{
    std::unique_lock<std::mutex> its_lock(mutex_);
    while (!blocked_)
    {
        condition_.wait(its_lock);
    }
    blocked_ = false;
    request_->set_service(vsomeip_test::TEST_SERVICE_SERVICE_ID);
    request_->set_instance(vsomeip_test::TEST_SERVICE_INSTANCE_ID);
    request_->set_method(vsomeip_test::TEST_SERVICE_METHOD_ID);

    for (uint32_t i = 0; i < number_of_messages_to_send_; i++)
    {
        app_->send(request_);
        VSOMEIP_INFO << "Client/Session [" << std::setw(4) << std::setfill('0')
                << std::hex << request_->get_client() << "/" << std::setw(4)
                << std::setfill('0') << std::hex << request_->get_session()
                << "] sent a request to Service [" << std::setw(4)
                << std::setfill('0') << std::hex << request_->get_service()
                << "." << std::setw(4) << std::setfill('0') << std::hex
                << request_->get_instance() << "]";
        number_of_sent_messages_++;
    }
    // wait until all messages have been acknowledged
    while (!blocked_)
    {
        condition_.wait(its_lock);
    }
    stop();
}

TEST(someip_header_factory_test, send_message_ten_times_test)
{
    bool use_tcp = false;
    header_factory_test_client test_client_(use_tcp);
    if (test_client_.init()) {
        test_client_.start();
        test_client_.join_sender_thread();
    }
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
