// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <condition_variable>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#include "suspend_resume_test.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class suspend_resume_test_client : public vsomeip_utilities::base_logger {
public:
    suspend_resume_test_client()
        : vsomeip_utilities::base_logger("SRTC", "SUSPEND RESUME TEST CLIENT"),
          name_("suspend_resume_test_client"),
          app_(vsomeip::runtime::get()->create_application(name_)),
          has_received_(false),
          runner_(std::bind(&suspend_resume_test_client::run, this)) {

    }

    void run_test() {

        register_state_handler();
        register_message_handler();
        register_availability_handler();

        start();

        {
            VSOMEIP_DEBUG << "Started.";
            std::unique_lock<std::mutex> its_lock(mutex_);
            auto r = cv_.wait_for(its_lock, std::chrono::seconds(10));
            VSOMEIP_DEBUG << "[TEST-cli] App Started: r=" << static_cast<int>(r);
            EXPECT_EQ(r, std::cv_status::no_timeout);
        }

        toggle();

        {
            VSOMEIP_DEBUG << "Toggled.";
            std::unique_lock<std::mutex> its_lock(mutex_);
            if (!has_received_) {
                auto r = cv_.wait_for(its_lock, std::chrono::seconds(10));
                VSOMEIP_DEBUG << "[TEST-cli] First Receive Validation: r=" << static_cast<int>(r);
                EXPECT_EQ(r, std::cv_status::no_timeout);
            } else {
                VSOMEIP_DEBUG << "[TEST-cli] Jumped received validation";
            }
        }

        VSOMEIP_DEBUG << "[TEST-cli] Sending suspend/resume: ";
        send_suspend();

        bool was_successful;
        {
            VSOMEIP_DEBUG << "Triggered suspend/resume.";
            // Wait for service to become availaber after suspend/resume.
            std::unique_lock<std::mutex> its_lock(mutex_);
            auto r = cv_.wait_for(its_lock, std::chrono::seconds(10));
            VSOMEIP_DEBUG << "[TEST-cli] Service Available after susp/resume: r=" << static_cast<int>(r);
            EXPECT_EQ(r, std::cv_status::no_timeout);

            // Wait for initial event after suspend/resume.
            r = cv_.wait_for(its_lock, std::chrono::seconds(10));
            VSOMEIP_DEBUG << "[TEST-cli] After susp/resume event validation: r=" << static_cast<int>(r);
            EXPECT_EQ(r, std::cv_status::no_timeout);

            was_successful = (r == std::cv_status::no_timeout);
        }

        if (was_successful)
            send_stop();

        stop();
    }

private:
    void register_state_handler() {

        app_->register_state_handler(
            std::bind(&suspend_resume_test_client::on_state, this, std::placeholders::_1));
    }

    void register_availability_handler() {

        app_->register_availability_handler(TEST_SERVICE, TEST_INSTANCE,
                std::bind(&suspend_resume_test_client::on_availability, this,
                    std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    }

    void register_message_handler() {

        app_->register_message_handler(TEST_SERVICE, TEST_INSTANCE, TEST_EVENT,
            std::bind(&suspend_resume_test_client::on_message, this,
                    std::placeholders::_1));
    }

    void start() {

        app_->init();
        cv_.notify_one();
    }

    void run() {

        {
            std::unique_lock<std::mutex> its_lock(mutex_);
            cv_.wait(its_lock);
        }

        app_->start();
    }

    void stop() {

        app_->stop();
        runner_.join();
    }

    void on_state(vsomeip::state_type_e _state) {

        VSOMEIP_DEBUG << __func__ << ": state="
            << (_state == vsomeip::state_type_e::ST_REGISTERED ?
                    "registered." : "NOT registered.");

        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            app_->request_event(TEST_SERVICE, TEST_INSTANCE, TEST_EVENT, { TEST_EVENTGROUP });
            app_->request_service(TEST_SERVICE, TEST_INSTANCE);
        }
    }

    void on_availability(vsomeip::service_t _service, vsomeip::instance_t _instance, bool _is_available) {

        static bool is_available(false);

        if (_service == TEST_SERVICE && _instance == TEST_INSTANCE) {

            VSOMEIP_DEBUG << __func__ << ": Test service is "
                    << (_is_available ? "available." : "NOT available.");

            if (_is_available) {
                VSOMEIP_DEBUG << "[TEST-cli] On availability will trigger cv";
                cv_.notify_one();
            } else if (is_available) {
                VSOMEIP_DEBUG << "[TEST-cli] On availability=false, clearing has_received";
                has_received_ = false;
            }
            is_available = _is_available;
        }
    }

    void on_message(const std::shared_ptr<vsomeip::message> &_message) {

        if (_message->get_service() == TEST_SERVICE
                && _message->get_instance() == TEST_INSTANCE
                && _message->get_method() == TEST_EVENT) {

            VSOMEIP_DEBUG << __func__ << ": Received event.";
            if (!has_received_) {
                has_received_ = true;
                VSOMEIP_DEBUG << "[TEST-cli] HasReceived Changed, triggering cv";
                cv_.notify_one();
            }
        }
    }

    void toggle() {
        VSOMEIP_DEBUG << "[TEST-cli] Toggle Start";
        app_->subscribe(TEST_SERVICE, TEST_INSTANCE, TEST_EVENTGROUP, TEST_MAJOR);
        std::this_thread::sleep_for(std::chrono::seconds(3));
        VSOMEIP_DEBUG << "[TEST-cli] Toggle Middle";
        app_->unsubscribe(TEST_SERVICE, TEST_INSTANCE, TEST_EVENTGROUP);
        app_->subscribe(TEST_SERVICE, TEST_INSTANCE, TEST_EVENTGROUP, TEST_MAJOR);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        app_->unsubscribe(TEST_SERVICE, TEST_INSTANCE, TEST_EVENTGROUP);
        app_->subscribe(TEST_SERVICE, TEST_INSTANCE, TEST_EVENTGROUP, TEST_MAJOR);
        VSOMEIP_DEBUG << "[TEST-cli] Toggle End";
    }


    void send_suspend() {

        auto its_message = vsomeip::runtime::get()->create_request(false);
        its_message->set_service(TEST_SERVICE);
        its_message->set_instance(TEST_INSTANCE);
        its_message->set_method(TEST_METHOD);
        its_message->set_interface_version(TEST_MAJOR);
        its_message->set_message_type(vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
        its_message->set_return_code(vsomeip::return_code_e::E_OK);

        vsomeip::byte_t its_data[] = { TEST_SUSPEND };
        auto its_payload = vsomeip::runtime::get()->create_payload();
        its_payload->set_data(its_data, sizeof(its_data));
        its_message->set_payload(its_payload);

        app_->send(its_message);

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    void send_stop() {

        auto its_message = vsomeip::runtime::get()->create_request(false);
        its_message->set_service(TEST_SERVICE);
        its_message->set_instance(TEST_INSTANCE);
        its_message->set_method(TEST_METHOD);
        its_message->set_interface_version(TEST_MAJOR);
        its_message->set_message_type(vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
        its_message->set_return_code(vsomeip::return_code_e::E_OK);

        vsomeip::byte_t its_data[] = { TEST_STOP };
        auto its_payload = vsomeip::runtime::get()->create_payload();
        its_payload->set_data(its_data, sizeof(its_data));
        its_message->set_payload(its_payload);

        app_->send(its_message);

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

private: // members
    std::string name_;
    std::shared_ptr<vsomeip::application> app_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool has_received_;
    std::thread runner_;
};

TEST(suspend_resume_test, fast)
{
    suspend_resume_test_client its_client;
    its_client.run_test();
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv) {

    VSOMEIP_DEBUG << "[TEST-cli] Starting Client";
    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
#endif
