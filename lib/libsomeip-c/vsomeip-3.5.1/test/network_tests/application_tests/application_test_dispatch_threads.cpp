// Copyright (C) 2015-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <future>

#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include "application_test_globals.hpp"
#include "someip_test_globals.hpp"

using namespace vsomeip;

class someip_application_detach_dispatch {

public:
    bool is_registered_;
    bool is_available_;
    std::atomic_bool is_forcefully_stopped_;
    std::atomic_bool is_finished_;
    std::shared_ptr<application> app_;
    std::condition_variable cv_;
    std::mutex mutex_;
    std::thread thread_;

    someip_application_detach_dispatch() { }
    ~someip_application_detach_dispatch() { }

    void init() {
        is_registered_ = false;
        is_available_ = false;

        app_ = runtime::get()->create_application("application_test_dispatch_threads");
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }

        app_->register_message_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
                                       vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                                       vsomeip_test::TEST_SERVICE_DETACH_METHOD_ID,
                                       std::bind(&someip_application_detach_dispatch::on_message,
                                                 this, std::placeholders::_1));

        app_->register_message_handler(
                vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                vsomeip_test::TEST_SERVICE_DETACH_METHOD_ID_LOOP_SHORT,
                std::bind(&someip_application_detach_dispatch::on_message_loop_short, this,
                          std::placeholders::_1));

        app_->register_message_handler(
                vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                vsomeip_test::TEST_SERVICE_DETACH_METHOD_ID_LOOP_LONG,
                std::bind(&someip_application_detach_dispatch::on_message_loop_long, this,
                          std::placeholders::_1));

        app_->register_state_handler(std::bind(&someip_application_detach_dispatch::on_state, this,
                                               std::placeholders::_1));
        app_->register_availability_handler(
                vsomeip_test::TEST_SERVICE_SERVICE_ID, vsomeip_test::TEST_SERVICE_INSTANCE_ID,
                std::bind(&someip_application_detach_dispatch::on_availability, this,
                          std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    }

    void cleanup() {
        app_->stop();
        app_.reset();
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    void on_state(vsomeip::state_type_e _state) {
        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            std::lock_guard<std::mutex> its_lock(mutex_);
            is_registered_ = true;
            cv_.notify_one();
        }
    }

    void on_availability(vsomeip::service_t _service, vsomeip::instance_t _instance,
                         bool _is_available) {
        (void)_service;
        (void)_instance;
        if (_is_available) {
            std::lock_guard<std::mutex> its_lock(mutex_);
            is_available_ = _is_available;
            cv_.notify_one();
        }
    }

    void on_message_loop_short(const std::shared_ptr<message>& _request) {
        (void)_request;
        VSOMEIP_INFO << "Processing something for 5 seconds";

        pthread_cleanup_push(handler_cbk, nullptr);

        is_finished_ = false;
        is_forcefully_stopped_ = false;

        for (int i = 0; i < 6; i++) {
            std::unique_lock<std::mutex> its_lock(mutex_);
            VSOMEIP_INFO << "Elapsed time: " << i << " seconds";

            // Call stop after 5 seconds
            if (i == 5) {
                VSOMEIP_INFO << "Sending stop signal after " << i << " seconds";
                app_->stop();
            }
            // using a condition variable instead of sleep_for so that ThreadSanitizer does not
            // raise any issues
            cv_.wait_for(its_lock, std::chrono::seconds(1));
            pthread_testcancel();
        }

        VSOMEIP_INFO << "Finished processing";
        is_finished_ = true;
        pthread_cleanup_pop(0);
    }

    void on_message_loop_long(const std::shared_ptr<message>& _request) {
        (void)_request;
        VSOMEIP_INFO << "Processing something for 50 seconds";

        pthread_cleanup_push(handler_cbk, this);

        is_finished_ = false;
        is_forcefully_stopped_ = false;

        for (int i = 0; i < 50; i++) {
            std::unique_lock<std::mutex> its_lock(mutex_);
            VSOMEIP_INFO << "Elapsed time: " << i << " seconds";

            // Call stop after 5 seconds
            if (i == 5) {
                VSOMEIP_INFO << "Sending stop signal after " << i << " seconds";
                app_->stop();
            }
            // using a condition variable instead of sleep_for so that ThreadSanitizer does not
            // raise any issues
            cv_.wait_for(its_lock, std::chrono::seconds(1));
            pthread_testcancel();
        }

        VSOMEIP_INFO << "Finished processing";
        is_finished_ = true;
        pthread_cleanup_pop(0);
    }

    void on_message(const std::shared_ptr<message>& _request) {
        (void)_request;
        VSOMEIP_INFO << "Processing something";

        std::unique_lock<std::mutex> its_lock(mutex_);
        // using a condition variable instead of sleep_for so that ThreadSanitizer does not raise
        // any issues
        cv_.wait_for(its_lock, std::chrono::milliseconds(100));
    }

    static void handler_cbk(void* arg) {
        if (arg != nullptr) {
            static_cast<someip_application_detach_dispatch*>(arg)->cleanup_handler(arg);
        }
    }

    void cleanup_handler(void* arg) {
        (void)arg;
        VSOMEIP_INFO << "Setting is_forcefully_stopped_ to true";
        is_forcefully_stopped_ = true;
    }

    void send_messages(vsomeip_v3::method_t method_id) {
        {
            std::unique_lock<std::mutex> its_lock(mutex_);
            while (!is_registered_) {
                if (std::cv_status::timeout == cv_.wait_for(its_lock, std::chrono::seconds(10))) {
                    ADD_FAILURE() << "Application wasn't registered in time!";
                    is_registered_ = true;
                }
            }
            app_->request_service(vsomeip_test::TEST_SERVICE_SERVICE_ID,
                                  vsomeip_test::TEST_SERVICE_INSTANCE_ID);
            app_->offer_service(vsomeip_test::TEST_SERVICE_SERVICE_ID,
                                vsomeip_test::TEST_SERVICE_INSTANCE_ID);
            while (!is_available_) {
                if (std::cv_status::timeout == cv_.wait_for(its_lock, std::chrono::seconds(10))) {
                    ADD_FAILURE() << "Service didn't become available in time!";
                    is_available_ = true;
                }
            }
        }

        create_send_request(method_id);
        create_send_request(vsomeip_test::TEST_SERVICE_DETACH_METHOD_ID);
    }

    void create_send_request(vsomeip_v3::method_t method_id) {
        std::shared_ptr<message> t = runtime::get()->create_request();
        t->set_service(vsomeip_test::TEST_SERVICE_SERVICE_ID);
        t->set_instance(vsomeip_test::TEST_SERVICE_INSTANCE_ID);
        t->set_method(method_id);
        app_->send(t);
    }

    void execute(char** argv) {
        // Create a shared memory object.
        boost::interprocess::shared_memory_object shm(
                boost::interprocess::open_only, // only create
                "SharedCV", // name
                boost::interprocess::read_write // read-write mode
        );

        try {
            // Map the whole shared memory in this process
            boost::interprocess::mapped_region region(
                    shm, // What to map
                    boost::interprocess::read_write // Map it as read-write
            );

            // Get the address of the mapped region
            void* addr = region.get_address();

            // Obtain a pointer to the shared structure
            application_test::dispatch_threads_sync* data =
                    static_cast<application_test::dispatch_threads_sync*>(addr);

            init();

            std::promise<bool> its_promise;
            std::thread t([&]() { app_->start(); });

            {
                boost::interprocess::scoped_lock<boost::interprocess::interprocess_mutex> lock(
                        data->mutex);

                // Set initial value of status_
                data->status_ = application_test::dispatch_threads_sync::TEST_FAILURE;

                // Read to argv[2] timeout and convert to tenths of a second
                int timeout = std::stoi(argv[2]) * 10;

                // argv[1] should be the type of test to run
                if (strcmp(argv[1], "force_abort") == 0) {
                    VSOMEIP_INFO << "Testing Force Abort";
                    send_messages(vsomeip_test::TEST_SERVICE_DETACH_METHOD_ID_LOOP_LONG);

                    for (int i = 0; i < timeout; i++) {

                        if (is_forcefully_stopped_ == true && is_finished_ == false) {
                            VSOMEIP_INFO << "Updating CV";
                            data->status_ =
                                    application_test::dispatch_threads_sync::SUCCESS_ABORTING;
                            data->cv.notify_all();
                            break;
                        }

                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }

                } else if (strcmp(argv[1], "wait_finish") == 0) {
                    VSOMEIP_INFO << "Testing Wait Finish";
                    send_messages(vsomeip_test::TEST_SERVICE_DETACH_METHOD_ID_LOOP_SHORT);

                    for (int i = 0; i < timeout; i++) {

                        if (is_forcefully_stopped_ == false && is_finished_ == true) {
                            VSOMEIP_INFO << "Updating CV";
                            data->status_ =
                                    application_test::dispatch_threads_sync::SUCCESS_WAITING;
                            data->cv.notify_all();
                            break;
                        }

                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                }
            }

            VSOMEIP_INFO << "Finishing execution";

            t.join();

            cleanup();

        } catch (boost::interprocess::interprocess_exception& ex) {
            FAIL() << ex.what();
        }
    }
};

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv) {
    (void)argc;

    someip_application_detach_dispatch exec;
    exec.execute(argv);
}
#endif
