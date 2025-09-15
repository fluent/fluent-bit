/*
 * Copyright (C) 2024 Xiaomi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef ANALYZER_ERROR_H_
#define ANALYZER_ERROR_H_

#include <string>
#include <string_view>
#include <vector>

#include "config.h"

namespace analyzer {

enum class ErrorLevel {
    Warning,
    Error,
};

static inline const char *
GetErrorLevelName(ErrorLevel error_level)
{
    switch (error_level) {
        case ErrorLevel::Warning:
            return "warning";
        case ErrorLevel::Error:
            return "error";
    }
    ANALYZER_UNREACHABLE;
}

class Error
{
  public:
    Error()
      : error_level_(ErrorLevel::Error)
    {}
    Error(ErrorLevel error_level, std::string_view message)
      : error_level_(error_level)
      , message_(message)
    {}

    ErrorLevel error_level_;
    std::string message_;
};

using Errors = std::vector<Error>;

} // namespace analyzer
#endif