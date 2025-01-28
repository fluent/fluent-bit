// Copyright (C) 2020 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef E2E_PROFILE_04_TEST_CLIENT_HPP_
#define E2E_PROFILE_04_TEST_CLIENT_HPP_

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

class e2e_profile_04_test_client {
public:
    e2e_profile_04_test_client();

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

    std::atomic<uint32_t> received_;
};

#endif // E2E_PROFILE_04_TEST_CLIENT_HPP_
