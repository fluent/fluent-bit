/*
 * Copyright (C) 2024 Xiaomi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef COMMON_H_
#define COMMON_H_

#include "string_format.h"

#define ANALYZER_FATAL(...) fprintf(stderr, __VA_ARGS__), exit(1)

#if WITH_EXCEPTIONS
#define ANALYZER_TRY try {
#define ANALYZER_CATCH_BAD_ALLOC \
    }                            \
    catch (std::bad_alloc &) {}
#define ANALYZER_CATCH_BAD_ALLOC_AND_EXIT \
    }                                     \
    catch (std::bad_alloc &) { ANALYZER_FATAL("Memory allocation failure.\n"); }
#else
#define ANALYZER_TRY
#define ANALYZER_CATCH_BAD_ALLOC
#define ANALYZER_CATCH_BAD_ALLOC_AND_EXIT
#endif

namespace analyzer {

struct ObjdumpOptions {
    bool info;
    bool text_size;
    bool details;
    bool compare;
    const char *file_name;
};

struct Result {
    enum Enum {
        Ok,
        Error,
    };

    Result()
      : Result(Ok)
    {}
    Result(Enum e)
      : enum_(e)
    {}
    operator Enum() const { return enum_; }
    Result &operator|=(Result rhs);

  private:
    Enum enum_;
};

inline Result
operator|(Result lhs, Result rhs)
{
    return (lhs == Result::Error || rhs == Result::Error) ? Result::Error
                                                          : Result::Ok;
}

inline Result &
Result::operator|=(Result rhs)
{
    enum_ = *this | rhs;
    return *this;
}

inline bool
Succeeded(Result result)
{
    return result == Result::Ok;
}

inline bool
Failed(Result result)
{
    return result == Result::Error;
}

#define CHECK_RESULT(expr)        \
    do {                          \
        if (Failed(expr)) {       \
            return Result::Error; \
        }                         \
    } while (0)

#define ERROR_IF(expr, ...)          \
    do {                             \
        if (expr) {                  \
            PrintError(__VA_ARGS__); \
            return Result::Error;    \
        }                            \
    } while (0)

#define ERROR_UNLESS(expr, ...) ERROR_IF(!(expr), __VA_ARGS__)

} // namespace analyzer
#endif
