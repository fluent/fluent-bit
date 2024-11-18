
// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef RESTART_ROUTING_TEST_CLIENT_HPP
#define RESTART_ROUTING_TEST_CLIENT_HPP

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <future>

class routing_restart_test_client {
public:
    routing_restart_test_client();
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
    bool is_available_;

    std::thread sender_;

    std::atomic<std::uint32_t> received_responses_;
    std::promise<void> all_responses_received_;
};

#endif // RESTART_ROUTING_TEST_CLIENT_HPP
