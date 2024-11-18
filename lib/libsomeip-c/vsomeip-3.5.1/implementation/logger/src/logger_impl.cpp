// Copyright (C) 2020-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iostream>

#include <vsomeip/runtime.hpp>

#include "../include/logger_impl.hpp"
#include "../../configuration/include/configuration.hpp"

namespace vsomeip_v3 {
namespace logger {

std::mutex logger_impl::mutex__;
std::string logger_impl::app_name__;

void
logger_impl::init(const std::shared_ptr<configuration> &_configuration) {
    std::scoped_lock its_lock {mutex__};
    auto its_logger = logger_impl::get();
    its_logger->set_configuration(_configuration);

    const char *its_name = getenv(VSOMEIP_ENV_APPLICATION_NAME);
    app_name__ = (nullptr != its_name) ? its_name : "";

#ifdef USE_DLT
#   define VSOMEIP_LOG_DEFAULT_CONTEXT_ID              "VSIP"
#   define VSOMEIP_LOG_DEFAULT_CONTEXT_NAME            "vSomeIP context"

#ifndef ANDROID
    std::string its_context_id = runtime::get_property("LogContext");
    if (its_context_id == "")
        its_context_id = VSOMEIP_LOG_DEFAULT_CONTEXT_ID;
    its_logger->register_context(its_context_id);
#endif
#endif
}

logger_impl::~logger_impl() {
#ifdef USE_DLT
#ifndef ANDROID
    DLT_UNREGISTER_CONTEXT(dlt_);
#endif
#endif
}

level_e logger_impl::get_loglevel() const {
    return cfg_level;
}

bool logger_impl::has_console_log() const {
    return cfg_console_enabled;
}

bool logger_impl::has_dlt_log() const {
    return cfg_dlt_enabled;
}

bool logger_impl::has_file_log() const {
    return cfg_file_enabled;
}

std::string logger_impl::get_logfile() const {
    std::scoped_lock its_lock {configuration_mutex_};
    return cfg_file_name;
}

const std::string& logger_impl::get_app_name() const {
    return app_name__;
}

std::unique_lock<std::mutex> logger_impl::get_app_name_lock() const {
    std::unique_lock its_lock(mutex__);
    return its_lock;
}

void logger_impl::set_configuration(const std::shared_ptr<configuration>& _configuration) {

    std::scoped_lock its_lock {configuration_mutex_};
    if (_configuration) {
        cfg_level = _configuration->get_loglevel();
        cfg_console_enabled = _configuration->has_console_log();
        cfg_dlt_enabled = _configuration->has_dlt_log();
        cfg_file_enabled = _configuration->has_file_log();
        cfg_file_name = _configuration->get_logfile();
    }
}

#ifdef USE_DLT
#ifndef ANDROID
void
logger_impl::log(level_e _level, const char *_data) {

    // Prepare log level
    DltLogLevelType its_level;
    switch (_level) {
    case level_e::LL_FATAL:
        its_level = DLT_LOG_FATAL;
        break;
    case level_e::LL_ERROR:
        its_level = DLT_LOG_ERROR;
        break;
    case level_e::LL_WARNING:
        its_level = DLT_LOG_WARN;
        break;
    case level_e::LL_INFO:
        its_level = DLT_LOG_INFO;
        break;
    case level_e::LL_DEBUG:
        its_level = DLT_LOG_DEBUG;
        break;
    case level_e::LL_VERBOSE:
        its_level = DLT_LOG_VERBOSE;
        break;
    default:
        its_level = DLT_LOG_DEFAULT;
    };

    std::scoped_lock its_lock {dlt_context_mutex_};
    DLT_LOG_STRING(dlt_, its_level, _data);
}

void logger_impl::register_context(const std::string& _context_id) {
    std::scoped_lock its_lock {dlt_context_mutex_};
    DLT_REGISTER_CONTEXT(dlt_, _context_id.c_str(), VSOMEIP_LOG_DEFAULT_CONTEXT_NAME);
}
#endif
#endif

static std::shared_ptr<logger_impl> *the_logger_ptr__(nullptr);
static std::mutex the_logger_mutex__;

std::shared_ptr<logger_impl>
logger_impl::get() {
#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
    std::scoped_lock its_lock {the_logger_mutex__};
#endif
    if (the_logger_ptr__ == nullptr) {
        the_logger_ptr__ = new std::shared_ptr<logger_impl>();
    }
    if (the_logger_ptr__ != nullptr) {
        if (!(*the_logger_ptr__)) {
            *the_logger_ptr__ = std::make_shared<logger_impl>();
        }
        return *the_logger_ptr__;
    }
    return nullptr;
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
static void logger_impl_teardown(void) __attribute__((destructor));
static void logger_impl_teardown(void)
{
    // TODO: This mutex is causing a crash due to changes in the way mutexes are defined.
    // Since this function only runs on the main thread, no mutex should be needed. Leaving a
    // comment pending a refactor.
    // std::scoped_lock its_lock(the_logger_mutex__);
    if (the_logger_ptr__ != nullptr) {
        the_logger_ptr__->reset();
        delete the_logger_ptr__;
        the_logger_ptr__ = nullptr;
    }
}
#endif

} // namespace logger
} // namespace vsomeip_v3
