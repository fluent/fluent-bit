// Copyright (C) 2014-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#include <gtest/gtest.h>

#include "climate_test_globals.hpp"

class client_sample {
public:
    client_sample(struct climate_test::service_info _service_info) :
            app_(vsomeip::runtime::get()->create_application()),
            service_info_(_service_info) {
    }

    bool init() {
        if (!app_->init()) {
            std::cerr << "Couldn't initialize application" << std::endl;
            return false;
        }

        app_->register_state_handler(
                std::bind(&client_sample::on_state, this,
                        std::placeholders::_1));

        app_->register_message_handler(
                vsomeip::ANY_SERVICE, service_info_.instance_id, vsomeip::ANY_METHOD,
                std::bind(&client_sample::on_message, this,
                        std::placeholders::_1));

        app_->register_availability_handler(service_info_.service_id, service_info_.instance_id,
                std::bind(&client_sample::on_availability,
                          this,
                          std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));

        std::set<vsomeip::eventgroup_t> its_groups;
        its_groups.insert(service_info_.eventgroup_id);
        app_->request_event(
                service_info_.service_id,
                service_info_.instance_id,
                service_info_.event_id,
                its_groups,
                vsomeip::event_type_e::ET_FIELD);
        app_->subscribe(service_info_.service_id, service_info_.instance_id, service_info_.eventgroup_id);

        return true;
    }

    void start() {
        app_->start();
    }

    void stop() {
        app_->clear_all_handler();
        app_->unsubscribe(service_info_.service_id, service_info_.instance_id, service_info_.eventgroup_id);
        app_->release_event(service_info_.service_id, service_info_.instance_id, service_info_.event_id);
        app_->release_service(service_info_.service_id, service_info_.instance_id);
        app_->stop();
    }

    void on_state(vsomeip::state_type_e _state) {
        VSOMEIP_INFO << "Application " << app_->get_name() << " is "
        << (_state == vsomeip::state_type_e::ST_REGISTERED ?
                "registered." : "deregistered.");

        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            app_->request_service(service_info_.service_id, service_info_.instance_id);
        }
    }

    void on_availability(vsomeip::service_t _service, vsomeip::instance_t _instance, bool _is_available) {
        VSOMEIP_INFO << "Service ["
                << std::setw(4) << std::setfill('0') << std::hex << _service << "." << _instance
                << "] is "
                << (_is_available ? "available." : "NOT available.")
                << std::endl;

        availability_handler_calls++;
    }

    void on_message(const std::shared_ptr<vsomeip::message> &_response) {
        std::stringstream its_message;
        its_message << "Received a notification for Event ["
                << std::setw(4)    << std::setfill('0') << std::hex
                << _response->get_service() << "."
                << std::setw(4) << std::setfill('0') << std::hex
                << _response->get_instance() << "."
                << std::setw(4) << std::setfill('0') << std::hex
                << _response->get_method() << "] to Client/Session ["
                << std::setw(4) << std::setfill('0') << std::hex
                << _response->get_client() << "/"
                << std::setw(4) << std::setfill('0') << std::hex
                << _response->get_session()
                << "] = ";
        std::shared_ptr<vsomeip::payload> its_payload =
                _response->get_payload();
        EXPECT_EQ(its_payload->get_length(), 5);
        its_message << "(" << std::dec << its_payload->get_length() << ") ";
        for (uint32_t i = 0; i < its_payload->get_length(); ++i) {
            its_message << std::hex << std::setw(2) << std::setfill('0')
                << (int) its_payload->get_data()[i] << " ";
        }

        if ((its_payload->get_length() % 5) == 0) {
            notifications_received++;
            if (notifications_received == 2) {
                // Send message to trigger second part of the test
                std::shared_ptr<vsomeip::message> its_set
                    = vsomeip::runtime::get()->create_message();
                its_set->set_message_type(vsomeip_v3::message_type_e::MT_REQUEST_NO_RETURN);
                its_set->set_service(service_info_.service_id);
                its_set->set_instance(service_info_.instance_id);
                its_set->set_method(service_info_.get_method_id);

                const vsomeip::byte_t its_data[]{0x07};
                std::shared_ptr<vsomeip::payload> its_set_payload
                    = vsomeip::runtime::get()->create_payload();
                its_set_payload->set_data(its_data, sizeof(its_data));
                its_set->set_payload(its_set_payload);
                app_->send(its_set);
                std::this_thread::sleep_for(climate_test::MSG_SEND_WAIT_INTERVAL);
            }

            if (notifications_received < 3) {
                request_release();
            } else if (notifications_received == 4) {
                // All expected notifications received, stop the client and send shutdown message to service
                EXPECT_EQ(availability_handler_calls, 9);

                std::shared_ptr<vsomeip::message> its_set
                    = vsomeip::runtime::get()->create_message();
                its_set->set_message_type(vsomeip_v3::message_type_e::MT_REQUEST_NO_RETURN);
                its_set->set_service(service_info_.service_id);
                its_set->set_instance(service_info_.instance_id);
                its_set->set_method(service_info_.shutdown_method_id);
                app_->send(its_set);
                std::this_thread::sleep_for(climate_test::MSG_SEND_WAIT_INTERVAL);
                stop();
            }
        }
    }

    void request_release() {
        app_->release_event(service_info_.service_id, service_info_.instance_id, service_info_.event_id);
        app_->release_service(service_info_.service_id, service_info_.instance_id);
        std::this_thread::sleep_for(climate_test::OFFER_CYCLE_INTERVAL);
        app_->request_service(service_info_.service_id, service_info_.instance_id);
        std::set<vsomeip::eventgroup_t> its_groups;
        its_groups.insert(service_info_.eventgroup_id);
        app_->request_event(
            service_info_.service_id,
            service_info_.instance_id,
            service_info_.event_id,
            its_groups,
            vsomeip::event_type_e::ET_FIELD);
        app_->subscribe(service_info_.service_id, service_info_.instance_id, service_info_.eventgroup_id);
    }

private:
    std::shared_ptr< vsomeip::application > app_;
    struct climate_test::service_info service_info_;
    uint8_t availability_handler_calls = 0;
    uint8_t notifications_received = 0;
};

TEST(someip_subscribe_notify_test_example, stop_without_unregister)
{
    client_sample its_sample(climate_test::service);

    if (its_sample.init()) {
        its_sample.start();
    }
}


#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
