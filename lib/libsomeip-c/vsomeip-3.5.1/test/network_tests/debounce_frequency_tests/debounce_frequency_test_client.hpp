// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef DEBOUNCE_FREQUENCY_TEST_CLIENT_HPP_
#define DEBOUNCE_FREQUENCY_TEST_CLIENT_HPP_

#include <condition_variable>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include "debounce_frequency_test_common.hpp"
#include <common/vsomeip_app_utilities.hpp>

class test_client : public vsomeip_utilities::base_vsip_app {

private:
    std::condition_variable condition_availability;
    std::mutex mutex;
    std::mutex event_counter_mutex;
    bool availability {false};

    int event_1_recv_messages {0};
    int event_2_recv_messages {0};

    void on_availability(vsomeip::service_t service_, vsomeip::instance_t instance_,
                         bool _is_available);
    void on_message(const std::shared_ptr<vsomeip::message>& _message);
    void stop_service();
    void unsubscribe_all();

public:
    test_client(const char* app_name_, const char* app_id_);

    int was_event1_recv();
    int was_event2_recv();
    void send_request();
    ~test_client();
};

#endif // DEBOUNCE_FREQUENCY_TEST_CLIENT_HPP_
