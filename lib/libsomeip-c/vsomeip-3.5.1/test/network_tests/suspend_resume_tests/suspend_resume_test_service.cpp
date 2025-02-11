// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <atomic>
#include <condition_variable>
#include <iomanip>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#include "suspend_resume_test.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

pid_t daemon_pid__;

class suspend_resume_test_service : public vsomeip_utilities::base_logger {
public:
    suspend_resume_test_service()
        : vsomeip_utilities::base_logger("ATCA", "APPLICATION TEST CLIENT AVAILABILITY"),
          name_("suspend_resume_test_service"),
          app_(vsomeip::runtime::get()->create_application(name_)),
          is_running_(true),
          is_unblocked_(false),
          runner_(std::bind(&suspend_resume_test_service::run, this)),
          sr_runner_(std::bind(&suspend_resume_test_service::sr_run, this)) {
    }

    void run_test() {

        register_state_handler();
        register_message_handler();
        register_subscription_handler();

        start();

        VSOMEIP_DEBUG << "Using daemon with pid=" << std::dec << daemon_pid__;

        {
            std::unique_lock<std::mutex> its_lock(mutex_);
            auto r = cv_.wait_for(its_lock, std::chrono::seconds(30));
            EXPECT_EQ(r, std::cv_status::no_timeout);
        }

        stop();
    }

private:
    void start() {

        app_->init();
        cv_.notify_one();
    }

    void stop() {

        is_running_ = false;
        sr_cv_.notify_one();

        app_->stop();

        runner_.join();
        sr_runner_.join();
    }

    void run() {

        {
            std::unique_lock<std::mutex> its_lock(mutex_);
            cv_.wait(its_lock);
        }

        app_->start();
    }

    void sr_run() {

        while (is_running_) {
            std::unique_lock<std::mutex> its_lock(sr_mutex_);
            sr_cv_.wait(its_lock);

            if (is_running_) {
                VSOMEIP_DEBUG << "send kill SIGUSR1 to PID: " << std::dec << daemon_pid__;
                kill(daemon_pid__, SIGUSR1);
                std::this_thread::sleep_for(std::chrono::seconds(5));
                VSOMEIP_DEBUG << "send kill SIGUSR2 to PID: " << std::dec << daemon_pid__;
                kill(daemon_pid__, SIGUSR2);
            }
        }
    }

    void register_state_handler() {

        app_->register_state_handler(
            std::bind(&suspend_resume_test_service::on_state, this, std::placeholders::_1));
    }

    void register_message_handler() {

        app_->register_message_handler(TEST_SERVICE, TEST_INSTANCE, TEST_METHOD,
            std::bind(&suspend_resume_test_service::on_message, this,
                std::placeholders::_1));
    }

    void register_subscription_handler() {

        app_->register_subscription_handler(TEST_SERVICE, TEST_INSTANCE, TEST_EVENTGROUP,
            std::bind(&suspend_resume_test_service::on_subscribe, this,
                    std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
    }

    void offer_service() {
        app_->offer_event(TEST_SERVICE, TEST_INSTANCE, TEST_EVENT, { TEST_EVENTGROUP },
                vsomeip::event_type_e::ET_FIELD,
                std::chrono::milliseconds::zero(), false, true, nullptr,
                vsomeip::reliability_type_e::RT_UNRELIABLE);

        vsomeip::byte_t its_data[] = { 0x1, 0x2, 0x3 };
        auto its_payload = vsomeip::runtime::get()->create_payload();
        its_payload->set_data(its_data, sizeof(its_data));
        app_->notify(TEST_SERVICE, TEST_INSTANCE, TEST_EVENT, its_payload);

        app_->offer_service(TEST_SERVICE, TEST_INSTANCE, TEST_MAJOR, TEST_MINOR);
    }

    // handler
    void on_state(vsomeip::state_type_e _state) {
        VSOMEIP_DEBUG << __func__ << "[TEST-srv]: state="
            << (_state == vsomeip::state_type_e::ST_REGISTERED ?
                    "registered." : "NOT registered.");

        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            offer_service();
        }
    }

    void on_message(const std::shared_ptr<vsomeip::message> &_message) {

        VSOMEIP_DEBUG << __func__ << "[TEST-srv]: Received "
                << std::hex << std::setw(4) << std::setfill('0')
                << _message->get_service()
                << std::hex << std::setw(4) << std::setfill('0')
                << _message->get_instance()
                << std::hex << std::setw(4) << std::setfill('0')
                << _message->get_method();

        if (_message->get_service() == TEST_SERVICE
                && _message->get_instance() == TEST_INSTANCE
                && _message->get_method() == TEST_METHOD) {

            if (_message->get_payload()->get_length() == 1) {

                vsomeip::byte_t its_control_byte(*_message->get_payload()->get_data());

                switch (its_control_byte) {
                case TEST_SUSPEND:
                    sr_cv_.notify_one();
                    break;
                case TEST_STOP:
                    cv_.notify_one();
                    break;
                default:
                    ;
                }
            }
        }
    }

    bool on_subscribe(vsomeip::client_t _client,
            vsomeip::uid_t _uid, vsomeip::gid_t _gid,
            bool _is_subscribe) {

        (void)_client;
        (void)_uid;
        (void)_gid;

        VSOMEIP_DEBUG << __func__ << "[TEST-srv]: is_subscribe=" << std::boolalpha << _is_subscribe;
        if (!_is_subscribe)
            std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        return true;
    }

private: // members
    std::string name_;
    std::shared_ptr<vsomeip::application> app_;
    std::atomic<bool> is_running_;
    bool is_unblocked_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::mutex sr_mutex_;
    std::condition_variable sr_cv_;
    std::thread runner_;
    std::thread sr_runner_;
};

TEST(suspend_resume_test, fast)
{
    suspend_resume_test_service its_service;
    its_service.run_test();
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv) {

    ::testing::InitGoogleTest(&argc, argv);

    daemon_pid__ = atoi(argv[1]);

    return RUN_ALL_TESTS();
}
#endif
