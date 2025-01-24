// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>
#include <future>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class application_test_daemon : public vsomeip_utilities::base_logger {
public:
    application_test_daemon() :
            vsomeip_utilities::base_logger("APTD", "APPLICATION TEST DAEMON"),
            app_(vsomeip::runtime::get()->create_application("daemon")) {
        if (!app_->init()) {
            ADD_FAILURE() << "[Daemon] Couldn't initialize application";
            return;
        }
        std::promise<bool> its_promise;
        application_thread_ = std::thread([&](){
            its_promise.set_value(true);
            app_->start();
        });
        EXPECT_TRUE(its_promise.get_future().get());
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        VSOMEIP_INFO << "[Daemon] Starting";
    }

    ~application_test_daemon() {
        application_thread_.join();
    }

    void stop() {
        VSOMEIP_INFO << "[Daemon] Stopping";
        app_->stop();
    }

private:
    std::shared_ptr<vsomeip::application> app_;
    std::thread application_thread_;
};
