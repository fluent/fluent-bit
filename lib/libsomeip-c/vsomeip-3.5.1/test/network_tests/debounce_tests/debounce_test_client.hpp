// Copyright (C) 2020 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef DEBOUNCE_TEST_CLIENT_HPP_
#define DEBOUNCE_TEST_CLIENT_HPP_

#include <condition_variable>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include "debounce_test_common.hpp"

class debounce_test_client {
public:
    debounce_test_client(debounce_test_id_e _test_id);

    bool init();
    void start();
    void stop();

    void run();
    void wait();

private:
    void on_availability(vsomeip::service_t _service, vsomeip::instance_t _instance,
                         bool _is_available);
    void on_message(const std::shared_ptr<vsomeip::message>& _message);

    void run_test();
    void unsubscribe_all();
    void stop_service();

    bool compare_payload(const std::shared_ptr<vsomeip::payload>& _payload,
                         std::size_t _index) const;

private:
    debounce_test_id_e test_id_;
    size_t index_;

    bool is_available_;

    std::mutex run_mutex_;
    std::condition_variable run_condition_;

    std::thread runner_;
    std::shared_ptr<vsomeip::application> app_;
};

#endif // DEBOUNCE_TEST_CLIENT_HPP_
