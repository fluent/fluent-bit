// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef E2E_PROFILE_04_TEST_SERVICE_HPP_
#define E2E_PROFILE_04_TEST_SERVICE_HPP_

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

class e2e_profile_04_test_service {
public:
    e2e_profile_04_test_service();

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

    bool blocked_;
    std::mutex mutex_;
    std::condition_variable condition_;

    std::thread offer_thread_;

    std::atomic<uint32_t> received_;
};

#endif // E2E_PROFILE_04_TEST_SERVICE_HPP_
