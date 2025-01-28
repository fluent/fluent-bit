// Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef BIGPAYLOADTESTCLIENT_HPP_
#define BIGPAYLOADTESTCLIENT_HPP_

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <atomic>

#include "big_payload_test_globals.hpp"
#include <vsomeip/internal/logger.hpp>

class big_payload_test_client
{
public:
    big_payload_test_client(bool _use_tcp, big_payload_test::test_mode _random_mode);
    bool init();
    void start();
    void stop();
    void join_sender_thread();
    void on_state(vsomeip::state_type_e _state);
    void on_availability(vsomeip::service_t _service,
            vsomeip::instance_t _instance, bool _is_available);
    void on_message(const std::shared_ptr<vsomeip::message> &_response);
    void send();
    void run();

private:
    std::shared_ptr<vsomeip::application> app_;
    std::shared_ptr<vsomeip::message> request_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool blocked_;
    bool is_available_;
    big_payload_test::test_mode test_mode_;
    std::uint32_t number_of_messages_to_send_;
    std::uint32_t number_of_sent_messages_;
    std::atomic<std::uint32_t> number_of_acknowledged_messages_;
    std::thread sender_;
    vsomeip::service_t service_id_;
};

#endif /* BIGPAYLOADTESTCLIENT_HPP_ */
