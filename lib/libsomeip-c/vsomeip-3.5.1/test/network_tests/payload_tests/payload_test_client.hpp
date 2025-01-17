// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef PAYLOADTESTCLIENT_HPP_
#define PAYLOADTESTCLIENT_HPP_

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include <cmath>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>

#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

#include "stopwatch.hpp"

class payload_test_client
{
public:
    payload_test_client(bool _use_tcp, bool _call_service_sync, std::uint32_t _sliding_window_size);
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
    void print_throughput();
    void send_messages_sync(std::unique_lock<std::mutex>& lk);
    void send_messages_async(std::unique_lock<std::mutex>& lk);
    void shutdown_service();
    std::uint32_t get_max_allowed_payload();

private:
    std::shared_ptr<vsomeip::application> app_;
    std::shared_ptr<vsomeip::message> request_;
    bool call_service_sync_;
    std::uint32_t sliding_window_size_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool blocked_;
    bool is_available_;
    const std::uint32_t number_of_messages_to_send_;
    std::uint32_t number_of_sent_messages_;
    std::uint32_t number_of_sent_messages_total_;
    std::uint32_t number_of_acknowledged_messages_;

    std::uint32_t current_payload_size_;

    stop_watch watch_;

    bool all_msg_acknowledged_;
    std::mutex all_msg_acknowledged_mutex_;
    std::condition_variable all_msg_acknowledged_cv_;

    std::thread sender_;

};

#endif /* PAYLOADTESTCLIENT_HPP_ */
