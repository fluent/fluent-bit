// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef MEMORY_TEST_SERVICE_HPP_
#define MEMORY_TEST_SERVICE_HPP_

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>
#include <common/vsomeip_app_utilities.hpp>

#include "memory_test_common.hpp"

class memory_test_service : public vsomeip_utilities::base_vsip_app
{
public:
    memory_test_service(const char *app_name_, const char *app_id_);
    void setup_app(const std::function<void(void)> executionHandler_);
    void message_sender(std::atomic<bool> &stop_checking_);

private:
    std::condition_variable condition_wait_start;
    std::condition_variable condition_wait_stop;
    std::mutex start_mutex;
    std::mutex stop_mutex;
    bool received_message { false };

    void on_start(const std::shared_ptr<vsomeip::message> /*&_message*/);
    void on_stop(const std::shared_ptr<vsomeip::message> /*&_message*/);
};
void check_memory(std::vector<std::uint64_t> &test_memory_);

#endif // MEMORY_TEST_SERVICE_HPP_
