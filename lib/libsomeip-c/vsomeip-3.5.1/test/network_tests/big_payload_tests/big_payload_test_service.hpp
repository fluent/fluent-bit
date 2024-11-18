// Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef BIGPAYLOADTESTSERVICE_HPP_
#define BIGPAYLOADTESTSERVICE_HPP_
#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <queue>

#include "big_payload_test_globals.hpp"
#include <vsomeip/internal/logger.hpp>


class big_payload_test_service
{
public:
    big_payload_test_service(big_payload_test::test_mode _test_mode);
    bool init();
    void start();
    void stop();
    void offer();
    void stop_offer();
    void join_offer_thread();
    void detach_offer_thread();
    void on_state(vsomeip::state_type_e _state);
    void on_message(const std::shared_ptr<vsomeip::message> &_request);
    void run();

private:
    std::shared_ptr<vsomeip::application> app_;
    bool is_registered_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool blocked_;
    big_payload_test::test_mode test_mode_;
    std::uint32_t number_of_received_messages_;
    std::thread offer_thread_;
    std::uint32_t expected_messages_;
    vsomeip::service_t service_id_;
    std::queue<std::shared_ptr<vsomeip::message>> incoming_requests_;
};

#endif /* BIGPAYLOADTESTSERVICE_HPP_ */
