// Copyright (C) 2015-2019 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef NPDUTESTSERVICE_HPP_
#define NPDUTESTSERVICE_HPP_
#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <chrono>
#include <deque>

class npdu_test_service
{
public:
    npdu_test_service(vsomeip::service_t _service_id,
                            vsomeip::instance_t _instance_id,
                            std::array<vsomeip::method_t, 4> _method_ids,
                            std::array<std::chrono::nanoseconds, 4> _debounce_times,
                            std::array<std::chrono::nanoseconds, 4> _max_retention_times);
    void init();
    void start();
    void stop();
    void offer();
    void stop_offer();
    void join_shutdown_thread();
    void on_state(vsomeip::state_type_e _state);
    template<int method_idx> void on_message(const std::shared_ptr<vsomeip::message> &_request);
    void on_message_shutdown(const std::shared_ptr<vsomeip::message> &_request);
    void run();

private:
    template<int method_idx> void check_times();
    template <int method_idx> void register_message_handler();

private:
    std::shared_ptr<vsomeip::application> app_;
    bool is_registered_;
    std::array<vsomeip::method_t, 4> method_ids_;
    std::array<std::chrono::nanoseconds, 4> debounce_times_;
    std::array<std::chrono::nanoseconds, 4> max_retention_times_;
    std::array<std::chrono::steady_clock::time_point, 4> timepoint_last_received_message_;
    std::array<std::mutex, 4> timepoint_mutexes_;
    std::deque<std::chrono::microseconds> undershot_debounce_times_;
    vsomeip::service_t service_id_;
    vsomeip::instance_t instance_id_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool blocked_;
    std::mutex shutdown_mutex_;
    std::condition_variable shutdown_condition_;
    bool allowed_to_shutdown_;
    std::uint32_t number_of_received_messages_;
    std::thread offer_thread_;
    std::thread shutdown_thread_;
};

#endif /* NPDUTESTSERVICE_HPP_ */
