// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>
#include <future>

#include "service.hpp"
#include "service_ids.hpp"

constexpr std::size_t PAYLOAD_SIZE = 1000UL;

service_t::service_t() :
    vsomeip_utilities::base_logger("SRV", "VSOMEIP SERVICE PROVIDER"),
    vsomeip_app(vsomeip::runtime::get()->create_application("service-sample")),
    payload(std::vector<uint8_t>(PAYLOAD_SIZE, 0)) {

    availability_table[SERVICE_ID] = false;
    availability_table[OTHER_SERVICE_ID] = false;
}

service_t::~service_t() {
    stop();
}

bool service_t::init() {
    if (!vsomeip_app->init()) {
        VSOMEIP_ERROR << "Couldn't initialize application" << std::endl;
        return false;
    }

    vsomeip_app->register_message_handler(
            SERVICE_ID, INSTANCE_ID, METHOD_ID,
            std::bind(&service_t::on_message, this, std::placeholders::_1));
    vsomeip_app->register_message_handler(
            OTHER_SERVICE_ID, OTHER_INSTANCE_ID, OTHER_METHOD_ID,
            std::bind(&service_t::on_message, this, std::placeholders::_1));

    vsomeip_app->register_availability_handler(
            SERVICE_ID, INSTANCE_ID,
            std::bind(&service_t::on_availability, this, std::placeholders::_1,
                      std::placeholders::_2, std::placeholders::_3));
    vsomeip_app->register_availability_handler(
            OTHER_SERVICE_ID, OTHER_INSTANCE_ID,
            std::bind(&service_t::on_availability, this, std::placeholders::_1,
                      std::placeholders::_2, std::placeholders::_3));

    vsomeip_app->offer_event(SERVICE_ID, INSTANCE_ID, EVENT_ID, {EVENTGROUP_ID},
                             vsomeip::event_type_e::ET_FIELD);
    vsomeip_app->offer_event(OTHER_SERVICE_ID, OTHER_INSTANCE_ID, EVENT_ID, {EVENTGROUP_ID},
                             vsomeip::event_type_e::ET_FIELD);

    vsomeip_app->request_service(SERVICE_ID, INSTANCE_ID);
    vsomeip_app->request_service(OTHER_SERVICE_ID, OTHER_INSTANCE_ID);

    return true;
}

void service_t::start() {
    worker = std::thread([&] { vsomeip_app->start(); });
}

void service_t::stop() {
    vsomeip_app->stop();
    if (worker.joinable()) {
        worker.join();
    }
}

std::future<bool> service_t::offer() {
    // Lock the entire function to not allow the on_availability callback to interfier while the
    // offer is being created
    std::lock_guard<std::mutex> lk(availability_mutex);

    VSOMEIP_INFO << "service_t::" << __func__;
    vsomeip_app->offer_service(SERVICE_ID, INSTANCE_ID, 0, 0);
    vsomeip_app->offer_service(OTHER_SERVICE_ID, OTHER_INSTANCE_ID, 0, 0);

    promise_availability = std::promise<bool>();
    auto future_availability = std::future<bool>(promise_availability.get_future());

    is_offering = true;
    return future_availability;
}

std::future<bool> service_t::stop_offer() {
    // Lock the entire function to not allow the on_availability callback to interfier while the
    // offer is being created
    std::lock_guard<std::mutex> lk(availability_mutex);

    VSOMEIP_INFO << "service_t::" << __func__;
    vsomeip_app->stop_offer_service(SERVICE_ID, INSTANCE_ID, 0, 0);
    vsomeip_app->stop_offer_service(OTHER_SERVICE_ID, OTHER_INSTANCE_ID, 0, 0);

    promise_availability = std::promise<bool>();
    auto future_availability = std::future<bool>(promise_availability.get_future());

    is_offering = false;
    return future_availability;
}

void service_t::on_message(const std::shared_ptr<vsomeip::message>& message) {
    std::lock_guard<std::mutex> lk(availability_mutex);

    payload.at(0)++;
    VSOMEIP_INFO << "service_t::" << __func__ << ": [" << std::hex << message->get_service() << "] "
                 << static_cast<int>(payload.at(0));

    auto vsomeip_payload = vsomeip::runtime::get()->create_payload(payload);
    auto its_response = vsomeip::runtime::get()->create_response(message);
    its_response->set_payload(vsomeip_payload);

    vsomeip_app->send(its_response);
}

void service_t::on_availability(vsomeip::service_t service, vsomeip::instance_t instance,
                                bool is_available) {
    std::lock_guard<std::mutex> lk(availability_mutex);

    VSOMEIP_INFO << "service_t::" << __func__ << " Service [" << std::setw(4) << std::setfill('0')
                 << std::hex << service << "." << instance << "] is "
                 << (is_available ? "available." : "NOT available.");

    availability_table[service] = is_available;

    // check if all services are in the same state of is_offering
    bool all_availabilities_confirmed = true;
    for (const auto& availability_entry : availability_table) {
        if (availability_entry.second != is_offering) {
            all_availabilities_confirmed = false;
        }
    }
    if (all_availabilities_confirmed) {
        // If all services are -> set promise
        promise_availability.set_value(is_offering);
    }
}
