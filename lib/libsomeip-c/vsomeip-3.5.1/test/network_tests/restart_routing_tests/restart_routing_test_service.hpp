// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef RESTART_ROUTING_TEST_SERVICE_HPP
#define RESTART_ROUTING_TEST_SERVICE_HPP

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

#include <thread>
#include <mutex>
#include <condition_variable>

class routing_restart_test_service {
public:
    routing_restart_test_service();
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
    std::condition_variable init_shutdown_condition_;
    std::condition_variable execute_shutdown_condition_;
    bool blocked_;
    bool init_shutdown_;
    bool all_received_;
    std::mutex shutdown_mutex_;
    std::mutex counter_mutex_;
    std::uint32_t shutdown_counter_;
    std::map<std::uint16_t, std::uint32_t> received_counter_;

    std::mutex number_of_received_messages_mutex_;
    std::uint32_t number_of_received_messages_;

    std::thread offer_thread_;
};

#endif // RESTART_ROUTING_TEST_SERVICE_HPP
