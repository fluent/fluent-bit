// Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include "restart_routing_test_client.hpp"

routing_restart_test_client::routing_restart_test_client()
    : app_(vsomeip::runtime::get()->create_application()),
      is_available_(false),
      sender_(std::bind(&routing_restart_test_client::run, this)),
      received_responses_(0) {

}

bool routing_restart_test_client::init() {
    if (!app_->init()) {
        ADD_FAILURE() << "Couldn't initialize application";
        return false;
    }

    app_->register_state_handler(
            std::bind(&routing_restart_test_client::on_state, this,
                    std::placeholders::_1));

    app_->register_message_handler(vsomeip::ANY_SERVICE,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID, vsomeip::ANY_METHOD,
            std::bind(&routing_restart_test_client::on_message, this,
                    std::placeholders::_1));

    app_->register_availability_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID,
            std::bind(&routing_restart_test_client::on_availability, this,
                    std::placeholders::_1, std::placeholders::_2,
                    std::placeholders::_3));
    return true;
}

void routing_restart_test_client::start() {
    VSOMEIP_INFO << "Starting...";

    app_->start();
}

void routing_restart_test_client::stop() {
    VSOMEIP_INFO << "Stopping...";

    shutdown_service();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    app_->clear_all_handler();
    app_->stop();
}

void routing_restart_test_client::on_state(vsomeip::state_type_e _state) {
    if(_state == vsomeip::state_type_e::ST_REGISTERED) {
        app_->request_service(vsomeip_test::TEST_SERVICE_SERVICE_ID,
                vsomeip_test::TEST_SERVICE_INSTANCE_ID, false);
    }
}

void routing_restart_test_client::on_availability(vsomeip::service_t _service,
        vsomeip::instance_t _instance, bool _is_available) {

    VSOMEIP_INFO << std::hex << "Client 0x" << app_->get_client()
            << " : Service [" << std::setw(4) << std::setfill('0') << std::hex
            << _service << "." << _instance << "] is "
            << (_is_available ? "available." : "NOT available.");

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

void routing_restart_test_client::on_message(const std::shared_ptr<vsomeip::message> &_response) {
    VSOMEIP_INFO << "Received a response from Service ["
                 << std::setw(4) << std::setfill('0') << std::hex << _response->get_service()
                 << "."
                 << std::setw(4) << std::setfill('0') << std::hex << _response->get_instance()
                 << "] to Client/Session ["
                 << std::setw(4) << std::setfill('0') << std::hex << _response->get_client()
                 << "/"
                 << std::setw(4) << std::setfill('0') << std::hex << _response->get_session()
                 << "]";

    if (_response->get_service() == vsomeip_test::TEST_SERVICE_SERVICE_ID &&
            _response->get_instance()  == vsomeip_test::TEST_SERVICE_INSTANCE_ID) {

        received_responses_++;
        if (received_responses_ == vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND_ROUTING_RESTART_TESTS) {
            VSOMEIP_WARNING << std::hex << app_->get_client()
                    << ": Received all messages ~> going down!";
            all_responses_received_.set_value();
        }
    }
}

void routing_restart_test_client::run() {
    std::uint32_t its_sent_requests(0);
    bool its_availability_timeout = false;
    while (its_sent_requests < vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND_ROUTING_RESTART_TESTS) {
        {
            std::unique_lock<std::mutex> its_lock(mutex_);
            while (!is_available_)
            {
                if (!condition_.wait_for(its_lock, std::chrono::milliseconds(10000),
                                         [this] { return is_available_; })) {
                    VSOMEIP_WARNING << "Service not available for 10s. Quit waiting";
                    its_availability_timeout = true;
                    break;
                }
                if (its_sent_requests > 0 && received_responses_ > 0
                    && its_sent_requests > received_responses_) {
                    VSOMEIP_WARNING << "Sent/Recv messages mismatch (" << its_sent_requests << "/"
                                    << received_responses_
                                    << ") : Resending non-responded requests";
                    its_sent_requests = received_responses_;
                }
            }
        }

        if (its_availability_timeout) {
            break;
        }
        auto request = vsomeip::runtime::get()->create_request(false);
        request->set_service(vsomeip_test::TEST_SERVICE_SERVICE_ID);
        request->set_instance(vsomeip_test::TEST_SERVICE_INSTANCE_ID);
        request->set_method(vsomeip_test::TEST_SERVICE_METHOD_ID);
        app_->send(request);

        its_sent_requests++;
        VSOMEIP_INFO << "Sent request " << its_sent_requests;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    if (std::future_status::ready == all_responses_received_.get_future().wait_for(std::chrono::milliseconds(10000))) {
        EXPECT_EQ(vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND_ROUTING_RESTART_TESTS,
                received_responses_);
        VSOMEIP_WARNING << "Received all answers";
    } else {
        ADD_FAILURE() << "Didn't receive all responses within time";
    }

    stop();
}

void routing_restart_test_client::join_sender_thread()
{
    if (sender_.joinable()) {
        sender_.join();
    }
}

void routing_restart_test_client::shutdown_service() {
    auto request = vsomeip::runtime::get()->create_request(false);
    request->set_service(vsomeip_test::TEST_SERVICE_SERVICE_ID);
    request->set_instance(vsomeip_test::TEST_SERVICE_INSTANCE_ID);
    request->set_method(vsomeip_test::TEST_SERVICE_METHOD_ID_SHUTDOWN);
    app_->send(request);
}

TEST(someip_restart_routing_test, request_response_over_restart)
{
    routing_restart_test_client test_client;
    if (test_client.init()) {
        test_client.start();
        test_client.join_sender_thread();
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
