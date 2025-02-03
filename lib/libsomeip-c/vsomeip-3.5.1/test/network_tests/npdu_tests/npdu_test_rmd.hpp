// Copyright (C) 2015-2019 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef NPDU_TESTS_NPDUTESTROUTINGMANAGERDAEMON_HPP_
#define NPDU_TESTS_NPDUTESTROUTINGMANAGERDAEMON_HPP_

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>

class npdu_test_rmd {

public:
    npdu_test_rmd();
    void init();
    void start();
    void stop();
    void on_state(vsomeip::state_type_e _state);
    void on_message_shutdown(const std::shared_ptr<vsomeip::message> &_request);
    void join_shutdown_thread();
    void run();

private:
    std::shared_ptr<vsomeip::application> app_;
    bool is_registered_;

    std::mutex mutex_;
    std::mutex mutex2_;
    std::condition_variable condition_;
    std::condition_variable condition2_;
    bool blocked_;
    bool blocked2_;
    std::thread offer_thread_;
    std::thread shutdown_thread_;

};

#endif /* NPDU_TESTS_NPDUTESTROUTINGMANAGERDAEMON_HPP_ */
