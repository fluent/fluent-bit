/*
 * Copyright (C) 2024 Xiaomi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef OPTION_PARSER_H_
#define OPTION_PARSER_H_

#include <functional>
#include <string>
#include <vector>

#include "config.h"

namespace analyzer {

class OptionParser
{
  public:
    enum class HasArgument { No, Yes };
    enum class ArgumentCount { One, OneOrMore, ZeroOrMore };

    struct Option;
    using Callback = std::function<void(const char *)>;
    using NullCallback = std::function<void()>;

    struct Option {
        Option(char short_name, const std::string &long_name,
               const std::string &metavar, HasArgument has_argument,
               const std::string &help, const Callback &);

        char short_name;
        std::string long_name;
        std::string metavar;
        bool has_argument;
        std::string help;
        Callback callback;
    };

    struct Argument {
        Argument(const std::string &name, ArgumentCount, const Callback &);

        std::string name;
        ArgumentCount count;
        Callback callback;
        int handled_count = 0;
    };

    explicit OptionParser(const char *program_name, const char *description);

    void AddOption(const Option &);
    void AddOption(char short_name, const char *long_name, const char *help,
                   const NullCallback &);
    void AddOption(const char *long_name, const char *help,
                   const NullCallback &);
    void AddOption(char short_name, const char *long_name, const char *metavar,
                   const char *help, const Callback &);

    void AddArgument(const std::string &name, ArgumentCount, const Callback &);
    void SetErrorCallback(const Callback &);
    void Parse(int argc, char *argv[]);
    void PrintHelp();

  private:
    static int Match(const char *s, const std::string &full, bool has_argument);
    void ANALYZER_PRINTF_FORMAT(2, 3) Errorf(const char *format, ...);
    void HandleArgument(size_t *arg_index, const char *arg_value);
    void DefaultError(const std::string &);

    std::string program_name_;
    std::string description_;
    std::vector<Option> options_;
    std::vector<Argument> arguments_;
    Callback on_error_;
};

} // namespace analyzer
#endif
