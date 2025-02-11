// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef DEBOUNCE_FREQUENCY_TEST_SERVICE_HPP_
#define DEBOUNCE_FREQUENCY_TEST_SERVICE_HPP_

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include "debounce_frequency_test_common.hpp"
#include <common/vsomeip_app_utilities.hpp>

class test_service : public vsomeip_utilities::base_vsip_app {
private:
    std::condition_variable condition_wait_start;
    std::mutex mutex;
    bool received_message {false};
    std::chrono::time_point<std::chrono::system_clock> start_time;
    bool event_1_sent_messages {false};
    bool event_2_sent_messages {false};

    void on_start(const std::shared_ptr<vsomeip::message> /*&_message*/);
    void on_stop(const std::shared_ptr<vsomeip::message> /*&_message*/);

public:
    test_service(const char* app_name_, const char* app_id_);

    void send_messages();
    bool was_event_1_sent();
    bool was_event_2_sent();
};

#endif // debounce_frequency_test_SERVICE_HPP_
