// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef LOCALROUTINGTESTSERVICE_HPP_
#define LOCALROUTINGTESTSERVICE_HPP_
#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>

#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class local_routing_test_service
{
public:
    local_routing_test_service(bool _use_static_routing);
    bool init();
    void start();
    void stop();
    void offer();
    void stop_offer();
    void join_offer_thread();
    void on_state(vsomeip::state_type_e _state);
    void on_message(const std::shared_ptr<vsomeip::message> &_request);
    void run();

private:
    std::shared_ptr<vsomeip::application> app_;
    bool is_registered_;
    bool use_static_routing_;

    bool blocked_;
    std::uint32_t number_of_received_messages_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::thread offer_thread_;
};

#endif /* LOCALROUTINGTESTSERVICE_HPP_ */
