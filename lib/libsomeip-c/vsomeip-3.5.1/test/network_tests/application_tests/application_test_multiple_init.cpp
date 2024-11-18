// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

/// @brief This test validates that no data race occurs when calling vsomeip::application_impl::init
///        on multiple applications, within the same process.
TEST(someip_application_init_test, multithread_init) {
    constexpr std::uint32_t thread_count = 128;
    std::vector<std::thread> vsomeip_applications;

    std::condition_variable start_cv;
    std::mutex start_mutex;
    std::atomic_bool start = false;

    // Prepare the init threads
    for (std::uint32_t t = 0; t < thread_count; ++t) {
        vsomeip_applications.emplace_back([&start_cv, &start_mutex, &start, t] {
            {
                std::unique_lock lk {start_mutex};
                start_cv.wait(lk, [&start] { return start.load(); });
            }
            std::stringstream app_name;
            app_name << "vsomeip_app_" << t;
            auto vsomeip_app = vsomeip::runtime::get()->create_application(app_name.str());

            EXPECT_TRUE(vsomeip_app->init()); // EXPECT also no crash
        });
    }

    // Start the init threads
    {
        std::scoped_lock lk {start_mutex};
        start = true;
        start_cv.notify_all();
    }

    // After test -> join threads
    for (auto& t : vsomeip_applications) {
        ASSERT_TRUE(t.joinable());
        t.join();
    }
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
