// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_LOGGER_CONFIGURATION_HPP_
#define VSOMEIP_V3_LOGGER_CONFIGURATION_HPP_

#include <memory>
#include <mutex>
#include <atomic>

#ifdef USE_DLT
#ifndef ANDROID
#include <dlt/dlt.h>
#endif
#endif

#include <vsomeip/internal/logger.hpp>

namespace vsomeip_v3 {

class configuration;

namespace logger {

class logger_impl {
public:
    VSOMEIP_IMPORT_EXPORT static void init(const std::shared_ptr<configuration> &_configuration);
    static std::shared_ptr<logger_impl> get();

    logger_impl() = default;
    ~logger_impl();

    void set_configuration(const std::shared_ptr<configuration>& _configuration);
    level_e get_loglevel() const;
    bool has_console_log() const;
    bool has_dlt_log() const;
    bool has_file_log() const;
    std::string get_logfile() const;

    const std::string& get_app_name() const;
    std::unique_lock<std::mutex> get_app_name_lock() const;

#ifdef USE_DLT
    void log(level_e _level, const char* _data);
    void register_context(const std::string& _context_id);

private:
    void enable_dlt(const std::string& _application, const std::string& _context);
#endif

private:
    static std::mutex mutex__;
    static std::string app_name__;

    mutable std::mutex configuration_mutex_;
    std::atomic<level_e> cfg_level {level_e::LL_NONE};
    std::atomic_bool cfg_console_enabled {false};
    std::atomic_bool cfg_dlt_enabled {false};
    std::atomic_bool cfg_file_enabled {false};
    std::string cfg_file_name {""};

#ifdef USE_DLT
#ifndef ANDROID
    std::mutex dlt_context_mutex_;
    DLT_DECLARE_CONTEXT(dlt_)
#endif
#endif
};

} // namespace logger
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_LOGGER_CONFIGURATION_HPP_
