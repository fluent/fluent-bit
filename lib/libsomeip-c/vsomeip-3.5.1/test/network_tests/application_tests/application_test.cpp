// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <future>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include "someip_test_globals.hpp"

using namespace vsomeip;

class someip_application_test: public ::testing::Test {
public:
    someip_application_test() :
            registered_(false) {

    }
protected:
    void SetUp() {
        app_ = runtime::get()->create_application("application_test");
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }

        app_->register_state_handler(
                std::bind(&someip_application_test::on_state, this,
                        std::placeholders::_1));
    }

    void on_state(vsomeip::state_type_e _state) {
        registered_ = (_state == vsomeip::state_type_e::ST_REGISTERED);
    }

    bool registered_;
    std::shared_ptr<application> app_;
};

/**
 * @test Start and stop application
 */
TEST_F(someip_application_test, start_stop_application)
{
    std::promise<bool> its_promise;
    std::thread t([&](){
        its_promise.set_value(true);
        app_->start();
    });
    EXPECT_TRUE(its_promise.get_future().get());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    app_->stop();
    t.join();
}

/**
 * @test Start and stop application multiple times
 */
TEST_F(someip_application_test, start_stop_application_multiple)
{
    for (int i = 0; i < 10; ++i) {
        std::promise<bool> its_promise;
        std::thread t([&]() {
            its_promise.set_value(true);
            app_->start();
        });
        EXPECT_TRUE(its_promise.get_future().get());
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        app_->stop();
        t.join();
    }
}

/**
 * @test Start and stop application multiple times and offer a service
 */
TEST_F(someip_application_test, start_stop_application_multiple_offer_service)
{
    for (int i = 0; i < 10; ++i) {
        std::promise<bool> its_promise;
        std::thread t([&]() {
            its_promise.set_value(true);
            app_->start();
        });
        EXPECT_TRUE(its_promise.get_future().get());
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        app_->offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        app_->stop_offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        app_->stop();
        t.join();
    }
}

/**
 * @test Try to start an already running application again
 */
TEST_F(someip_application_test, restart_without_stopping)
{
    std::promise<bool> its_promise;
    std::thread t([&]() {
        its_promise.set_value(true);
        app_->start();

    });
    EXPECT_TRUE(its_promise.get_future().get());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    VSOMEIP_WARNING << "An error message should appear now";
    // should print error
    app_->start();
    app_->stop();
    t.join();
}

/**
 * @test Try to stop a running application twice
 */
TEST_F(someip_application_test, stop_application_twice)
{
    std::promise<bool> its_promise;
    std::thread t([&]() {
        its_promise.set_value(true);
        app_->start();

    });
    EXPECT_TRUE(its_promise.get_future().get());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    app_->stop();
    t.join();
    app_->stop();
}

/**
 * @test Checks whether watchdog handler is invoked (regularly) also after restarting.
 */
TEST_F(someip_application_test, watchdog_handler)
{
    std::atomic<int> cb_count(0);
    auto wd_handler = [&] () {
        ++cb_count;
    };

    app_->set_watchdog_handler(std::cref(wd_handler), std::chrono::seconds(1));

    std::promise<bool> its_promise;
    std::thread t([&]() {
        its_promise.set_value(true);
        app_->start();
    });
    EXPECT_TRUE(its_promise.get_future().get());

    // wait till watchdog handler has been invoked once
    while (0 == cb_count.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    ASSERT_EQ(1, cb_count.load());

    // clear handler (must not be called again)
    app_->set_watchdog_handler(nullptr, std::chrono::seconds::zero());

    // wait doubled interval (used previously)..
    std::this_thread::sleep_for(std::chrono::seconds(2));
    // .. to ensure it was not called again
    ASSERT_EQ(1, cb_count.load());

    // enable handler again
    app_->set_watchdog_handler(std::cref(wd_handler), std::chrono::seconds(1));

    // wait till watchdog handler has been invoked again (2nd time)
    while (1 == cb_count.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    app_->stop();
    t.join();

    // wait doubled interval (used previously)..
    std::this_thread::sleep_for(std::chrono::seconds(2));
    // .. to ensure it was not called after stop()
    ASSERT_EQ(2, cb_count.load());

    // restart application (w/ watchdog handler still set)
    std::promise<bool> its_promise2;
    std::thread t2([&]() {
        its_promise2.set_value(true);
        app_->start();
    });
    EXPECT_TRUE(its_promise2.get_future().get());

    // wait till watchdog handler has been invoked again (3rd time)
    while (2 == cb_count.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    ASSERT_EQ(3, cb_count.load());

    // clear handler again (must not be called again), this time via zero interval
    app_->set_watchdog_handler(std::cref(wd_handler), std::chrono::seconds::zero());

    // wait doubled interval (used previously)..
    std::this_thread::sleep_for(std::chrono::seconds(2));
    // .. to ensure it was not called again
    ASSERT_EQ(3, cb_count.load());

    app_->stop();
    t2.join();
}

class someip_application_shutdown_test: public ::testing::Test {

protected:
    void SetUp() {
        is_registered_ = false;
        is_available_ = false;

        app_ = runtime::get()->create_application("application_test");
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }

        app_->register_message_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
                vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                vsomeip_test::TEST_SERVICE_METHOD_ID_SHUTDOWN,
                std::bind(&someip_application_shutdown_test::on_message_shutdown, this,
                        std::placeholders::_1));

        app_->register_state_handler(
                std::bind(&someip_application_shutdown_test::on_state, this,
                        std::placeholders::_1));
        app_->register_availability_handler(
                vsomeip_test::TEST_SERVICE_SERVICE_ID,
                vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                std::bind(&someip_application_shutdown_test::on_availability,
                        this, std::placeholders::_1, std::placeholders::_2,
                        std::placeholders::_3));

        shutdown_thread_ = std::thread(&someip_application_shutdown_test::send_shutdown_message, this);

        app_->start();
    }

    void TearDown() {
        shutdown_thread_.join();
        app_->stop();
        app_.reset();
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    void on_state(vsomeip::state_type_e _state) {
        if(_state == vsomeip::state_type_e::ST_REGISTERED)
        {
            std::lock_guard<std::mutex> its_lock(mutex_);
            is_registered_ = true;
            cv_.notify_one();
        }
    }

    void on_availability(vsomeip::service_t _service,
                         vsomeip::instance_t _instance, bool _is_available) {
        (void)_service;
        (void)_instance;
        if(_is_available) {
            std::lock_guard<std::mutex> its_lock(mutex_);
            is_available_ = _is_available;
            cv_.notify_one();
        }
    }

    void on_message_shutdown(const std::shared_ptr<message>& _request)
    {
        (void)_request;
        VSOMEIP_INFO << "Shutdown method was called, going down now.";
        app_->clear_all_handler();
        app_->stop();
    }

    void send_shutdown_message() {
        {
            std::unique_lock<std::mutex> its_lock(mutex_);
            while (!is_registered_) {
                if (std::cv_status::timeout
                        == cv_.wait_for(its_lock, std::chrono::seconds(10))) {
                    ADD_FAILURE()<< "Application wasn't registered in time!";
                    is_registered_ = true;
                }
            }
            app_->request_service(vsomeip_test::TEST_SERVICE_SERVICE_ID,
                    vsomeip_test::TEST_SERVICE_INSTANCE_ID);
            app_->offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID,
                    vsomeip_test::TEST_SERVICE_INSTANCE_ID);
            while (!is_available_) {
                if (std::cv_status::timeout
                        == cv_.wait_for(its_lock, std::chrono::seconds(10))) {
                    ADD_FAILURE()<< "Service didn't become available in time!";
                    is_available_ = true;
                }
            }
        }

        std::shared_ptr<message> r = runtime::get()->create_request();
        r->set_service(vsomeip_test::TEST_SERVICE_SERVICE_ID);
        r->set_instance(vsomeip_test::TEST_SERVICE_INSTANCE_ID);
        r->set_method(vsomeip_test::TEST_SERVICE_METHOD_ID_SHUTDOWN);
        app_->send(r);
    }

    bool is_registered_;
    bool is_available_;
    std::shared_ptr<application> app_;
    std::condition_variable cv_;
    std::mutex mutex_;
    std::thread shutdown_thread_;
};

class someip_application_exception_test: public ::testing::Test {

protected:
    void SetUp() {
        is_registered_ = false;
        is_available_ = false;
        exception_method_called_ = false;

        app_ = runtime::get()->create_application("application_test");
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }

        app_->register_message_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
                vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                vsomeip_test::TEST_SERVICE_METHOD_ID_SHUTDOWN,
                std::bind(&someip_application_exception_test::on_message_shutdown, this,
                        std::placeholders::_1));
        app_->register_message_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
                vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                vsomeip_test::TEST_SERVICE_METHOD_ID_SHUTDOWN+1,
                std::bind(&someip_application_exception_test::on_message_exception, this,
                        std::placeholders::_1));

        app_->register_state_handler(
                std::bind(&someip_application_exception_test::on_state, this,
                        std::placeholders::_1));
        app_->register_availability_handler(
                vsomeip_test::TEST_SERVICE_SERVICE_ID,
                vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                std::bind(&someip_application_exception_test::on_availability,
                        this, std::placeholders::_1, std::placeholders::_2,
                        std::placeholders::_3));

        shutdown_thread_ = std::thread(&someip_application_exception_test::send_shutdown_message, this);

        app_->start();
    }

    void TearDown() {
        shutdown_thread_.join();
        app_->stop();
        app_.reset();
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    void on_state(vsomeip::state_type_e _state) {
        if(_state == vsomeip::state_type_e::ST_REGISTERED)
        {
            std::lock_guard<std::mutex> its_lock(mutex_);
            is_registered_ = true;
            cv_.notify_one();
        }
    }

    void on_availability(vsomeip::service_t _service,
                         vsomeip::instance_t _instance, bool _is_available) {
        (void)_service;
        (void)_instance;
        if(_is_available) {
            std::lock_guard<std::mutex> its_lock(mutex_);
            is_available_ = _is_available;
            cv_.notify_one();
        }
    }

    void on_message_shutdown(const std::shared_ptr<message>& _request)
    {
        (void)_request;
        VSOMEIP_INFO << "Shutdown method was called, going down now.";
        app_->clear_all_handler();
        app_->stop();
    }

    void on_message_exception(const std::shared_ptr<message>& _request)
    {
        (void)_request;
        {
            std::lock_guard<std::mutex> its_lock(mutex_);
            exception_method_called_ = true;
            cv_.notify_one();
        }
        throw std::invalid_argument("something went terribly wrong");
    }

    void send_shutdown_message() {
        {
            std::unique_lock<std::mutex> its_lock(mutex_);
            while(!is_registered_) {
                cv_.wait(its_lock);
            }
            app_->request_service(vsomeip_test::TEST_SERVICE_SERVICE_ID,
                    vsomeip_test::TEST_SERVICE_INSTANCE_ID);
            app_->offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID,
                    vsomeip_test::TEST_SERVICE_INSTANCE_ID);
            while(!is_available_) {
                cv_.wait(its_lock);
            }
        }

        std::shared_ptr<message> r = runtime::get()->create_request();
        // call method which throws exception
        r->set_service(vsomeip_test::TEST_SERVICE_SERVICE_ID);
        r->set_instance(vsomeip_test::TEST_SERVICE_INSTANCE_ID);
        r->set_method(vsomeip_test::TEST_SERVICE_METHOD_ID_SHUTDOWN+1);
        app_->send(r);

        {
            std::unique_lock<std::mutex> its_lock(mutex_);
            while (!exception_method_called_) {
                cv_.wait(its_lock);
            }
        }


        //shutdown test
        r->set_service(vsomeip_test::TEST_SERVICE_SERVICE_ID);
        r->set_instance(vsomeip_test::TEST_SERVICE_INSTANCE_ID);
        r->set_method(vsomeip_test::TEST_SERVICE_METHOD_ID_SHUTDOWN);
        app_->send(r);
    }

    bool is_registered_;
    bool is_available_;
    bool exception_method_called_;
    std::shared_ptr<application> app_;
    std::condition_variable cv_;
    std::mutex mutex_;
    std::thread shutdown_thread_;
};

/**
 * @test Stop the application through a method invoked from a dispatcher thread
 */
TEST_F(someip_application_shutdown_test, stop_application_from_dispatcher_thread) {

}

/**
 * @test Catch unhandled exceptions from invoked handlers
 */
TEST_F(someip_application_exception_test, catch_exception_in_invoked_handler) {

}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
