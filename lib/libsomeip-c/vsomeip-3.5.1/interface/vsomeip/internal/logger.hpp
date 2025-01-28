// Copyright (C) 2020-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_LOGGER_HPP_
#define VSOMEIP_V3_LOGGER_HPP_

#include <chrono>
#include <cstdint>
#include <mutex>
#include <ostream>
#include <sstream>
#include <streambuf>

#include <vsomeip/export.hpp>

namespace vsomeip_v3 {
namespace logger {

enum class VSOMEIP_IMPORT_EXPORT level_e : std::uint8_t {
    LL_NONE = 0,
    LL_FATAL = 1,
    LL_ERROR = 2,
    LL_WARNING = 3,
    LL_INFO = 4,
    LL_DEBUG = 5,
    LL_VERBOSE = 6
};

class message
    : public std::ostream {

public:
    VSOMEIP_IMPORT_EXPORT message(level_e _level);
    VSOMEIP_IMPORT_EXPORT ~message();

private:
    class buffer : public std::streambuf {
    public:
        int_type overflow(int_type);
        std::streamsize xsputn(const char *, std::streamsize);

        std::stringstream data_;
    };

    std::chrono::system_clock::time_point when_;
    buffer buffer_;
    level_e level_;
    static std::mutex mutex__;
};

} // namespace logger
} // namespace vsomeip_v3

#define VSOMEIP_FATAL   vsomeip_v3::logger::message(vsomeip_v3::logger::level_e::LL_FATAL)
#define VSOMEIP_ERROR   vsomeip_v3::logger::message(vsomeip_v3::logger::level_e::LL_ERROR)
#define VSOMEIP_WARNING vsomeip_v3::logger::message(vsomeip_v3::logger::level_e::LL_WARNING)
#define VSOMEIP_INFO    vsomeip_v3::logger::message(vsomeip_v3::logger::level_e::LL_INFO)
#define VSOMEIP_DEBUG   vsomeip_v3::logger::message(vsomeip_v3::logger::level_e::LL_DEBUG)
#define VSOMEIP_TRACE   vsomeip_v3::logger::message(vsomeip_v3::logger::level_e::LL_VERBOSE)

#define VSOMEIP_LOG_DEFAULT_APPLICATION_ID      "VSIP"
#define VSOMEIP_LOG_DEFAULT_APPLICATION_NAME    "vSomeIP application|SysInfra|IPC"

#endif // VSOMEIP_V3_LOGGER_HPP_
