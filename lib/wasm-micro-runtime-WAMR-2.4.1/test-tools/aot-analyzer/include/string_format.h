/*
 * Copyright (C) 2024 Xiaomi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef STRING_FORMAT_H_
#define STRING_FORMAT_H_

#include <cstdarg>
#include <string>
#include <vector>

#include "config.h"

#define PRIstringview "%.*s"
#define ANALYZER_PRINTF_STRING_VIEW_ARG(x) \
    static_cast<int>((x).length()), (x).data()

#define PRItypecode "%s%#x"

#define ANALYZER_DEFAULT_SNPRINTF_ALLOCA_BUFSIZE 128
#define ANALYZER_SNPRINTF_ALLOCA(buffer, len, format)                   \
    va_list args;                                                       \
    va_list args_copy;                                                  \
    va_start(args, format);                                             \
    va_copy(args_copy, args);                                           \
    char fixed_buf[ANALYZER_DEFAULT_SNPRINTF_ALLOCA_BUFSIZE];           \
    char *buffer = fixed_buf;                                           \
    size_t len =                                                        \
        analyzer_vsnprintf(fixed_buf, sizeof(fixed_buf), format, args); \
    va_end(args);                                                       \
    if (len + 1 > sizeof(fixed_buf)) {                                  \
        buffer = static_cast<char *>(alloca(len + 1));                  \
        len = analyzer_vsnprintf(buffer, len + 1, format, args_copy);   \
    }                                                                   \
    va_end(args_copy)

namespace analyzer {

inline std::string ANALYZER_PRINTF_FORMAT(1, 2)
    StringPrintf(const char *format, ...)
{
    va_list args;
    va_list args_copy;
    va_start(args, format);
    va_copy(args_copy, args);
    size_t len = analyzer_vsnprintf(nullptr, 0, format, args) + 1;
    std::vector<char> buffer(len);
    va_end(args);
    analyzer_vsnprintf(buffer.data(), len, format, args_copy);
    va_end(args_copy);
    return std::string(buffer.data(), len - 1);
}

} // namespace analyzer
#endif
