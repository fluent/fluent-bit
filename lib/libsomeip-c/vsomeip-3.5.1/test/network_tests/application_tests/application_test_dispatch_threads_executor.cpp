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
#include <boost/date_time/posix_time/posix_time.hpp>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include "application_test_globals.hpp"
#include "someip_test_globals.hpp"

using namespace vsomeip;

class someip_application_detach_dispatch_executor : public ::testing::Test {

protected:
    void SetUp() { VSOMEIP_INFO << "Setting up test"; }

    void TearDown() { VSOMEIP_INFO << "Tearing down"; }

    int get_process_pid(std::string process_name) {
        std::string file_name = "/tmp/" + process_name + ".pid";
        int pid = -1;
        FILE* file = fopen(file_name.c_str(), "r");

        if (file) {
            if (fscanf(file, "%d", &pid) != 1) { // Check that fscanf successfully read one integer
                std::cerr << "Failed to read PID from file" << std::endl;
                pid = -1; // Indicate failure
            }
            fclose(file);
        } else {
            std::cerr << "Failed to open PID file" << std::endl;
        }

        return pid;
    }

    // Erase previous shared memory and schedule erasure on exit

    boost::interprocess::shared_memory_object shm;

    std::condition_variable cv_;
    std::mutex mutex_;
};

/**
 * @test Force detaching of dispatcher threads with long processing times
 */
TEST_F(someip_application_detach_dispatch_executor, dispatch_thread_detached_forcefully_stopped) {

    struct shm_remove {
        shm_remove() { boost::interprocess::shared_memory_object::remove("SharedCV"); }
        ~shm_remove() { boost::interprocess::shared_memory_object::remove("SharedCV"); }
    } remover;

    // Create a shared memory object.
    boost::interprocess::shared_memory_object shm(
            boost::interprocess::open_or_create, // only create
            "SharedCV", // name
            boost::interprocess::read_write // read-write mode
    );

    // Timeout to pass into the test
    int seconds_to_timeout = 20;

    // Define how long should the test wait for the condition variable to be set
    boost::posix_time::ptime timeout = boost::posix_time::second_clock::local_time()
            + boost::posix_time::seconds(seconds_to_timeout);

    try {
        // Set size
        shm.truncate(sizeof(application_test::dispatch_threads_sync));

        // Map the whole shared memory in this process
        boost::interprocess::mapped_region region(
                shm, // What to map
                boost::interprocess::read_write // Map it as read-write
        );

        // Get the address of the mapped region
        void* addr = region.get_address();

        // Construct the shared structure in memory
        application_test::dispatch_threads_sync* data =
                new (addr) application_test::dispatch_threads_sync;

        {
            boost::interprocess::scoped_lock<boost::interprocess::interprocess_mutex> lock(
                    data->mutex);

            std::string exec_cmd = "./application_test_dispatch_threads_starter.sh force_abort "
                    + std::to_string(seconds_to_timeout);
            std::cout << std::flush;

            EXPECT_EQ(system(exec_cmd.c_str()), 0);

            EXPECT_EQ(data->cv.timed_wait(lock, timeout, [&] { return data->status_; }),
                      application_test::dispatch_threads_sync::SUCCESS_ABORTING);

            // Retrieve the PID
            int pid = get_process_pid("application_test_dispatch_threads");

            std::string check_cmd = "kill -0 " + std::to_string(pid);

            if (system(check_cmd.c_str())
                == 0) { // If the process exists, the command will return 0
                std::string kill_cmd = "kill -9 " + std::to_string(pid);
                EXPECT_EQ(system(kill_cmd.c_str()), 0);
            }
        }
    } catch (boost::interprocess::interprocess_exception& ex) {
        std::cout << ex.what() << std::endl;
    }
}

/**
 * @test Force detaching of dispatcher threads with but dispatcher finishes processing
 */
TEST_F(someip_application_detach_dispatch_executor, dispatch_thread_detached_finishes_execution) {

    struct shm_remove {
        shm_remove() { boost::interprocess::shared_memory_object::remove("SharedCV"); }
        ~shm_remove() { boost::interprocess::shared_memory_object::remove("SharedCV"); }
    } remover;

    // Create a shared memory object.
    boost::interprocess::shared_memory_object shm(
            boost::interprocess::open_or_create, // only create
            "SharedCV", // name
            boost::interprocess::read_write // read-write mode
    );

    VSOMEIP_INFO << "Starting test";

    // Timeout to pass into the test
    int seconds_to_timeout = 8;

    // Define how long should the test wait for the condition variable to be set
    boost::posix_time::ptime timeout = boost::posix_time::second_clock::local_time()
            + boost::posix_time::seconds(seconds_to_timeout);

    VSOMEIP_INFO << "Timeout set to " << timeout;

    try {
        // Set size
        shm.truncate(sizeof(application_test::dispatch_threads_sync));

        // Map the whole shared memory in this process
        boost::interprocess::mapped_region region(
                shm, // What to map
                boost::interprocess::read_write // Map it as read-write
        );

        // Get the address of the mapped region
        void* addr = region.get_address();

        // Construct the shared structure in memory
        application_test::dispatch_threads_sync* data =
                new (addr) application_test::dispatch_threads_sync;

        {
            boost::interprocess::scoped_lock<boost::interprocess::interprocess_mutex> lock(
                    data->mutex);

            std::string exec_cmd = "./application_test_dispatch_threads_starter.sh wait_finish "
                    + std::to_string(seconds_to_timeout);

            ASSERT_EQ(system(exec_cmd.c_str()), 0);

            EXPECT_EQ(data->cv.timed_wait(lock, timeout, [&] { return data->status_; }),
                      application_test::dispatch_threads_sync::SUCCESS_WAITING);

            // Retrieve the PID
            int pid = get_process_pid("application_test_dispatch_threads");

            std::string check_cmd = "kill -0 " + std::to_string(pid);

            if (system(check_cmd.c_str())
                == 0) { // If the process exists, the command will return 0
                std::string kill_cmd = "kill -9 " + std::to_string(pid);
                EXPECT_EQ(system(kill_cmd.c_str()), 0);
            }
        }
    } catch (boost::interprocess::interprocess_exception& ex) {
        std::cout << ex.what() << std::endl;
    }
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
