// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef LAZY_LOAD_TEST_CLIENT_HPP
#define LAZY_LOAD_TEST_CLIENT_HPP

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>
#include <vsomeip/vsomeip.hpp>

#include "../someip_test_globals.hpp"

class lazy_load_test_client {
public:
    lazy_load_test_client();
    bool init();
    void start();
    void stop();

    void on_state(vsomeip::state_type_e _state);
    void on_availability(vsomeip::service_t _service,
            vsomeip::instance_t _instance, bool _is_available);
    void on_message(const std::shared_ptr<vsomeip::message> &_response);

    void run();
    void join_sender_thread();

private:
    void shutdown_service();

    std::shared_ptr<vsomeip::application> app_;

    std::mutex mutex_;
    std::condition_variable condition_;
    bool current_service_availability_status_;

    std::thread sender_;

    std::atomic<std::uint32_t> received_responses_;
    std::atomic<std::uint32_t> received_allowed_events_;

    const std::uint16_t METHOD_TO_BE_REFUSED = 0x888;
    const std::uint16_t SERVICE_TO_BE_REFUSED = 0x111;
    const std::uint16_t TEST_INSTANCE_LAZY = 0x02;
    const std::uint16_t EXPECTED_EVENTS = 0x01;

    const std::uint16_t EVENT_GROUP = 0x01;
    const std::uint16_t EVENT_TO_ACCEPT = 0x8001;
    const std::uint16_t EVENT_TO_REFUSE = 0x8002;

    const std::uint16_t NUMBER_OF_MESSAGES_TO_SEND = 10;

};

#endif // LAZY_LOAD_TEST_CLIENT_HPP
