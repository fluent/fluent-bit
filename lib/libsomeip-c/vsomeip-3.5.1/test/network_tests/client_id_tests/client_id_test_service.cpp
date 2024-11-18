// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <chrono>
#include <condition_variable>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>
#include <map>
#include <algorithm>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#include "client_id_test_globals.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>


class client_id_test_service : public vsomeip_utilities::base_logger {
public:
    client_id_test_service(struct client_id_test::service_info _service_info) :
            vsomeip_utilities::base_logger("CITS", "CLIENT ID TEST SERVICE"),
            service_info_(_service_info),
            app_(vsomeip::runtime::get()->create_application()),
            blocked_(false),
            offer_thread_(std::bind(&client_id_test_service::run, this)),
            stopped_(false),
            stop_thread_(std::bind(&client_id_test_service::wait_for_stop, this)) {
        if (!app_->init()) {
            offer_thread_.detach();
            stop_thread_.detach();
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }
        app_->register_state_handler(
                std::bind(&client_id_test_service::on_state, this,
                        std::placeholders::_1));
        app_->register_message_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.method_id,
                std::bind(&client_id_test_service::on_request, this,
                        std::placeholders::_1));
        app_->register_message_handler(vsomeip::ANY_SERVICE,
                service_info_.instance_id, vsomeip::ANY_METHOD,
                std::bind(&client_id_test_service::on_response, this,
                        std::placeholders::_1));

        for(const auto& i : client_id_test::service_infos) {
            if ((i.service_id == service_info_.service_id
                    && i.instance_id == service_info_.instance_id)
                    || (i.service_id == 0xFFFF && i.instance_id == 0xFFFF)) {
                continue;
            }
            app_->request_service(i.service_id, i.instance_id);
            app_->register_availability_handler(i.service_id, i.instance_id,
                    std::bind(&client_id_test_service::on_availability, this,
                            std::placeholders::_1, std::placeholders::_2,
                            std::placeholders::_3));

            other_services_available_[std::make_pair(i.service_id, i.instance_id)] = false;
            other_services_received_response_[std::make_pair(i.service_id, i.method_id)] = 0;
            other_services_received_request_[i.offering_client] = 0;
        }

        app_->start();
    }

    ~client_id_test_service() {
        if (offer_thread_.joinable()) {
            offer_thread_.join();
        }
        if (stop_thread_.joinable()) {
            stop_thread_.join();
        }
    }

    void offer() {
        app_->offer_service(service_info_.service_id, service_info_.instance_id);
    }

    void stop_offer() {
        app_->stop_offer_service(service_info_.service_id, service_info_.instance_id);
    }

    void on_state(vsomeip::state_type_e _state) {
        VSOMEIP_INFO << "Application " << app_->get_name() << " is "
        << (_state == vsomeip::state_type_e::ST_REGISTERED ?
                "registered." : "deregistered.");

        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            std::lock_guard<std::mutex> its_lock(mutex_);
            blocked_ = true;
            condition_.notify_one();
        }
    }

    void on_availability(vsomeip::service_t _service,
                         vsomeip::instance_t _instance, bool _is_available) {
        if(_is_available) {
            VSOMEIP_INFO
            << "[" << std::setw(4) << std::setfill('0') << std::hex
            << service_info_.service_id << "] Service ["
            << std::setw(4) << std::setfill('0') << std::hex << _service << "." << _instance
            << "] is "
            << (_is_available ? "available." : "NOT available.");

            auto its_service = other_services_available_.find(std::make_pair(_service, _instance));
            if(its_service != other_services_available_.end()) {
                its_service->second = true;
            }

            if(std::all_of(other_services_available_.cbegin(),
                           other_services_available_.cend(),
                           [](const std::map<std::pair<vsomeip::service_t,
                                   vsomeip::instance_t>, bool>::value_type& v) {
                                return v.second;})) {
                std::lock_guard<std::mutex> its_lock(mutex_);
                blocked_ = true;
                condition_.notify_one();
            }
        }
    }

    void on_request(const std::shared_ptr<vsomeip::message> &_message) {
        if(_message->get_message_type() == vsomeip::message_type_e::MT_REQUEST) {
            VSOMEIP_DEBUG
            << "[" << std::setw(4) << std::setfill('0') << std::hex
                        << service_info_.service_id
            << "] Received a request with Client/Session [" << std::setw(4)
            << std::setfill('0') << std::hex << _message->get_client() << "/"
            << std::setw(4) << std::setfill('0') << std::hex
            << _message->get_session() << "]";
            std::shared_ptr<vsomeip::message> its_response = vsomeip::runtime::get()
            ->create_response(_message);
            app_->send(its_response);

            other_services_received_request_[_message->get_client()]++;
            if(all_responses_and_requests_received()) {
                std::lock_guard<std::mutex> its_lock(stop_mutex_);
                stopped_ = true;
                stop_condition_.notify_one();
            }
        }
    }

    void on_response(const std::shared_ptr<vsomeip::message> &_message) {
        if(_message->get_message_type() == vsomeip::message_type_e::MT_RESPONSE) {
            VSOMEIP_DEBUG
            << "[" << std::setw(4) << std::setfill('0') << std::hex
                        << service_info_.service_id
            << "] Received a response with Client/Session [" << std::setw(4)
            << std::setfill('0') << std::hex << _message->get_client() << "/"
            << std::setw(4) << std::setfill('0') << std::hex
            << _message->get_session() << "] from Service/Method ["
            << std::setw(4) << std::setfill('0') << std::hex
            << _message->get_service() << "/" << std::setw(4) << std::setfill('0')
            << std::hex << _message->get_method() << "]";
            other_services_received_response_[std::make_pair(_message->get_service(),
                                                             _message->get_method())]++;

            if(all_responses_and_requests_received()) {
                std::lock_guard<std::mutex> its_lock(stop_mutex_);
                stopped_ = true;
                stop_condition_.notify_one();
            }
        }
    }

    bool all_responses_and_requests_received() {
        const bool responses = std::all_of(
               other_services_received_response_.cbegin(),
               other_services_received_response_.cend(),
               [](const std::map<std::pair<vsomeip::service_t,
                       vsomeip::method_t>, std::uint32_t>::value_type& v)
               { return v.second == client_id_test::messages_to_send;});
        const bool requests = std::all_of(
                other_services_received_request_.cbegin(),
                other_services_received_request_.cend(),
                [](const std::map<vsomeip::client_t, std::uint32_t>::value_type& v)
                { return v.second == client_id_test::messages_to_send;});
        return (responses && requests);
    }

    void run() {
        std::unique_lock<std::mutex> its_lock(mutex_);
        while (!blocked_) {
            condition_.wait(its_lock);
        }
        blocked_ = false;

        VSOMEIP_DEBUG  << "[" << std::setw(4) << std::setfill('0') << std::hex
                    << service_info_.service_id << "] Offering";
        offer();


        while (!blocked_) {
            condition_.wait(its_lock);
        }
        blocked_ = false;

        VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                << service_info_.service_id << "] Sending";
        // send a message to all other services
        for (int var = 0; var < client_id_test::messages_to_send; ++var) {
            for(const client_id_test::service_info& i: client_id_test::service_infos) {
                if ((i.service_id == service_info_.service_id
                                && i.instance_id == service_info_.instance_id)
                        || (i.service_id == 0xFFFF && i.instance_id == 0xFFFF)) {
                    continue;
                }
                std::shared_ptr<vsomeip::message> msg = vsomeip::runtime::get()->create_request();
                msg->set_service(i.service_id);
                msg->set_instance(i.instance_id);
                msg->set_method(i.method_id);
                app_->send(msg);
                VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0')
                        << std::hex << service_info_.service_id
                        << "] Sending a request to Service/Method ["
                        << std::setw(4) << std::setfill('0') << std::hex
                        << i.service_id << "/" << std::setw(4) << std::setfill('0')
                        << std::hex << i.instance_id << "]";
            }
        }

        while (!blocked_) {
            condition_.wait(its_lock);
        }
        blocked_ = false;
    }

    void wait_for_stop() {
        std::unique_lock<std::mutex> its_lock(stop_mutex_);
        while (!stopped_) {
            stop_condition_.wait(its_lock);
        }
        VSOMEIP_INFO << "[" << std::setw(4) << std::setfill('0') << std::hex
                << service_info_.service_id
                << "] Received responses and requests from all other services, going down";

        // let offer thread exit
        {
            std::lock_guard<std::mutex> its_lock(mutex_);
            blocked_ = true;
            condition_.notify_one();
        }

        std::this_thread::sleep_for(std::chrono::seconds(3));
        app_->clear_all_handler();
        app_->stop();
    }

private:
    client_id_test::service_info service_info_;
    std::shared_ptr<vsomeip::application> app_;
    std::map<std::pair<vsomeip::service_t, vsomeip::instance_t>, bool> other_services_available_;
    std::map<std::pair<vsomeip::service_t, vsomeip::method_t>, std::uint32_t> other_services_received_response_;
    std::map<vsomeip::client_t, std::uint32_t> other_services_received_request_;

    bool blocked_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::thread offer_thread_;

    bool stopped_;
    std::mutex stop_mutex_;
    std::condition_variable stop_condition_;
    std::thread stop_thread_;
};

static int service_number;

TEST(someip_client_id_test, send_ten_messages_to_service)
{
    client_id_test_service its_sample(
            client_id_test::service_infos[static_cast<size_t>(service_number)]);
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    if(argc < 2) {
        std::cerr << "Please specify a service number, like: " << argv[0] << " 2" << std::endl;
        std::cerr << "Valid service numbers are in the range of [1,6]" << std::endl;
        return 1;
    }
    service_number = std::stoi(std::string(argv[1]), nullptr);
    return RUN_ALL_TESTS();
}
#endif
