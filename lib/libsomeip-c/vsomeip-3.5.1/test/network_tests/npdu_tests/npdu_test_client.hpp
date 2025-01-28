// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef PAYLOADTESTCLIENT_HPP_
#define NPDUTESTCLIENT_HPP_

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <map>

#include "../npdu_tests/npdu_test_globals.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class npdu_test_client
{
public:
    npdu_test_client(bool _use_tcp, bool _call_service_sync,
                           std::uint32_t _sliding_window_size,
                           bool _wait_for_replies,
                           std::array<std::array<std::chrono::milliseconds, 4>, 4> _applicative_debounce);
    ~npdu_test_client();
    void init();
    void start();
    void stop();
    void join_sender_thread();
    void on_state(vsomeip::state_type_e _state);
    template<int service_idx> void on_availability(vsomeip::service_t _service,
                                                   vsomeip::instance_t _instance,
                                                   bool _is_available);
    template<int service_idx, int method_idx> void on_message(
            const std::shared_ptr<vsomeip::message> &_response);
    template<int service_idx> void send();
    template<int service_idx> void run();

private:
    template<int service_idx> void send_messages_sync();
    template<int service_idx, int method_idx> std::thread start_send_thread_sync();
    template<int service_idx> void send_messages_async();
    template<int service_idx, int method_idx> std::thread start_send_thread_async();
    template<int service_idx> void send_messages_and_dont_wait_for_reply();
    std::uint32_t get_max_allowed_payload();
    template<int service_idx> void register_availability_handler();
    template<int service_idx> void register_message_handler_for_all_service_methods();
    template<int service_idx, int method_idx> void register_message_handler();
    template<int service_idx, int method_idx>
        std::thread start_send_thread();
    void wait_for_all_senders();

private:
    std::shared_ptr<vsomeip::application> app_;
    std::shared_ptr<vsomeip::message> request_;
    bool call_service_sync_;
    bool wait_for_replies_;
    std::uint32_t sliding_window_size_;

    std::array<std::mutex, npdu_test::service_ids.size()> mutexes_;
    std::array<std::condition_variable, npdu_test::service_ids.size()> conditions_;
    std::array<bool, npdu_test::service_ids.size()> blocked_;
    std::array<bool, npdu_test::service_ids.size()> is_available_;
    const std::uint32_t number_of_messages_to_send_;
    std::uint32_t number_of_sent_messages_[npdu_test::service_ids.size()];
    std::array<std::array<std::uint32_t, npdu_test::method_ids[0].size()>,
            npdu_test::service_ids.size()> number_of_acknowledged_messages_;
    std::array<std::array<std::mutex, npdu_test::method_ids[0].size()>,
            npdu_test::service_ids.size()> number_of_acknowledged_messages_mutexes_;

    std::array<std::uint32_t, npdu_test::service_ids.size()> current_payload_size_;

    std::array<std::array<bool, npdu_test::method_ids[0].size()>,
            npdu_test::service_ids.size()> all_msg_acknowledged_;
    std::array<std::array<std::mutex, npdu_test::method_ids[0].size()>,
            npdu_test::service_ids.size()> all_msg_acknowledged_mutexes_;
    std::array<std::array<std::unique_lock<std::mutex>, npdu_test::method_ids[0].size()>,
            npdu_test::service_ids.size()> all_msg_acknowledged_unique_locks_;
    std::array<
            std::array<std::condition_variable,
                    npdu_test::method_ids[0].size()>,
            npdu_test::service_ids.size()> all_msg_acknowledged_cvs_;
    std::array<std::uint32_t, 4> acknowledgements_;
    std::array<std::array<std::chrono::milliseconds, 4>, 4> applicative_debounce_;
    std::array<
            std::array<std::shared_ptr<vsomeip::payload>,
                    npdu_test::method_ids[0].size()>,
            npdu_test::service_ids.size()> payloads_;
    std::array<
            std::array<std::vector<vsomeip::byte_t>,
                    npdu_test::method_ids[0].size()>,
            npdu_test::service_ids.size()> payload_data_;
    std::array<std::thread, npdu_test::service_ids.size()> senders_;
    std::mutex finished_mutex_;
    std::array<bool, npdu_test::service_ids.size()> finished_;
    std::thread finished_waiter_;
};

#endif /* NPDUTESTCLIENT_HPP_ */
