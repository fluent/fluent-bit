// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef LAZY_LOAD_TEST_SERVICE_HPP
#define LAZY_LOAD_TEST_SERVICE_HPP

#include <condition_variable>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>
#include <vsomeip/vsomeip.hpp>

#include "../someip_test_globals.hpp"

class lazy_load_test_service {
public:
    lazy_load_test_service();
    bool init();
    void start();
    void stop();
    void offer();
    void stop_offer();
    void join_offer_thread();
    void on_state(vsomeip::state_type_e _state);
    void on_message(const std::shared_ptr<vsomeip::message> &_request);
    void on_message_shutdown(const std::shared_ptr<vsomeip::message> &_request);
    void run();

private:
    std::shared_ptr<vsomeip::application> app_;
    bool is_registered_;

    std::mutex mutex_;
    std::condition_variable condition_;
    bool blocked_;
    std::uint32_t number_of_received_messages_;
    std::thread offer_thread_;

    const std::uint16_t SERVICE_TO_BE_REFUSED = 0x111;
    const std::uint16_t TEST_INSTANCE_LAZY = 0x02;

    const std::uint16_t EVENT_GROUP = 0x01;
    const std::uint16_t EVENT_TO_ACCEPT_LAZY = 0x8002;
    const std::uint16_t EVENT_TO_ACCEPT_DEFAULT = 0x8001;

    // Twice as big as messages to send, account for all messages from both clients
    const std::uint16_t NUMBER_OF_MESSAGES_TO_RECEIVE = 20;
};

#endif // LAZY_LOAD_TEST_SERVICE_HPP
