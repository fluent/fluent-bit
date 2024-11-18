// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef MEMORY_TEST_CLIENT_HPP_
#define MEMORY_TEST_CLIENT_HPP_

#include <condition_variable>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include "memory_test_common.hpp"
#include <common/vsomeip_app_utilities.hpp>

class memory_test_client : public vsomeip_utilities::base_vsip_app
{
public:
    memory_test_client(const char *app_name_, const char *app_id_,
                       std::map<vsomeip::event_t, int> map_events_);
    void send_request(std::atomic<bool> &stop_checking_);

    ~memory_test_client();

private:
    std::condition_variable condition_availability;
    std::mutex availability_mutex;
    std::mutex event_counter_mutex;
    bool availability { false };
    int received_messages_counter { 0 };
    std::map<vsomeip::event_t, int> map_events;
    std::chrono::time_point<std::chrono::system_clock> sec;
    void on_availability(vsomeip::service_t service_, vsomeip::instance_t instance_,
                         bool is_available_);
    void on_message(const std::shared_ptr<vsomeip::message> &message_);
    void stop_service();
    void unsubscribe_all();

};

#endif // MEMORY_TEST_CLIENT_HPP_
