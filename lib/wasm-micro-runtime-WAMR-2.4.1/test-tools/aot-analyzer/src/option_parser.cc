/*
 * Copyright (C) 2024 Xiaomi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "option_parser.h"

#include "common.h"
#include "config.h"
#include "string_format.h"

namespace analyzer {

OptionParser::Option::Option(char short_name, const std::string &long_name,
                             const std::string &metavar,
                             HasArgument has_argument, const std::string &help,
                             const Callback &callback)
  : short_name(short_name)
  , long_name(long_name)
  , metavar(metavar)
  , has_argument(has_argument == HasArgument::Yes)
  , help(help)
  , callback(callback)
{}

OptionParser::Argument::Argument(const std::string &name, ArgumentCount count,
                                 const Callback &callback)
  : name(name)
  , count(count)
  , callback(callback)
{}

OptionParser::OptionParser(const char *program_name, const char *description)
  : program_name_(program_name)
  , description_(description)
  , on_error_([this](const std::string &message) { DefaultError(message); })
{
    AddOption("help", "Print this help message", [this]() {
        PrintHelp();
        exit(0);
    });
    AddOption("version", "Print version information", []() {
        printf("%s\n", ANALYZER_VERSION_STRING);
        exit(0);
    });
}

void
OptionParser::AddOption(const Option &option)
{
    options_.emplace_back(option);
}

void
OptionParser::AddArgument(const std::string &name, ArgumentCount count,
                          const Callback &callback)
{
    arguments_.emplace_back(name, count, callback);
}

void
OptionParser::AddOption(char short_name, const char *long_name,
                        const char *help, const NullCallback &callback)
{
    Option option(short_name, long_name, std::string(), HasArgument::No, help,
                  [callback](const char *) { callback(); });
    AddOption(option);
}

void
OptionParser::AddOption(const char *long_name, const char *help,
                        const NullCallback &callback)
{
    Option option('\0', long_name, std::string(), HasArgument::No, help,
                  [callback](const char *) { callback(); });
    AddOption(option);
}

void
OptionParser::AddOption(char short_name, const char *long_name,
                        const char *metavar, const char *help,
                        const Callback &callback)
{
    Option option(short_name, long_name, metavar, HasArgument::Yes, help,
                  callback);
    AddOption(option);
}

void
OptionParser::SetErrorCallback(const Callback &callback)
{
    on_error_ = callback;
}

int
OptionParser::Match(const char *s, const std::string &full, bool has_argument)
{
    int i;
    for (i = 0;; i++) {
        if (full[i] == '\0') {
            if (s[i] == '\0') {
                return i + 1;
            }

            if (!(has_argument && s[i] == '=')) {
                return -1;
            }
            break;
        }
        if (s[i] == '\0') {
            break;
        }
        if (s[i] != full[i]) {
            return -1;
        }
    }
    return i;
}

void
OptionParser::Errorf(const char *format, ...)
{
    ANALYZER_SNPRINTF_ALLOCA(buffer, length, format);
    std::string msg(program_name_);
    msg += ": ";
    msg += buffer;
    msg += "\nTry '--help' for more information.";
    on_error_(msg.c_str());
}

void
OptionParser::DefaultError(const std::string &message)
{
    ANALYZER_FATAL("%s\n", message.c_str());
}

void
OptionParser::HandleArgument(size_t *arg_index, const char *arg_value)
{
    if (*arg_index >= arguments_.size()) {
        Errorf("unexpected argument '%s'", arg_value);
        return;
    }
    Argument &argument = arguments_[*arg_index];
    argument.callback(arg_value);
    argument.handled_count++;

    if (argument.count == ArgumentCount::One) {
        (*arg_index)++;
    }
}

void
OptionParser::Parse(int argc, char *argv[])
{
    size_t arg_index = 0;
    bool processing_options = true;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (!processing_options || arg[0] != '-') {
            HandleArgument(&arg_index, arg);
            continue;
        }

        if (arg[1] == '-') {
            if (arg[2] == '\0') {
                processing_options = false;
                continue;
            }
            int best_index = -1;
            int best_length = 0;
            int best_count = 0;
            for (size_t j = 0; j < options_.size(); ++j) {
                const Option &option = options_[j];
                if (!option.long_name.empty()) {
                    int match_length =
                        Match(&arg[2], option.long_name, option.has_argument);
                    if (match_length > best_length) {
                        best_index = j;
                        best_length = match_length;
                        best_count = 1;
                    }
                    else if (match_length == best_length && best_length > 0) {
                        best_count++;
                    }
                }
            }

            if (best_count > 1) {
                Errorf("ambiguous option '%s'", arg);
                continue;
            }
            else if (best_count == 0) {
                Errorf("unknown option '%s'", arg);
                continue;
            }

            const Option &best_option = options_[best_index];
            const char *option_argument = nullptr;
            if (best_option.has_argument) {
                if (arg[best_length + 1] != 0 && arg[best_length + 2] == '=') {
                    option_argument = &arg[best_length + 3];
                }
                else {
                    if (i + 1 == argc || argv[i + 1][0] == '-') {
                        Errorf("option '--%s' requires argument",
                               best_option.long_name.c_str());
                        continue;
                    }
                    ++i;
                    option_argument = argv[i];
                }
            }
            best_option.callback(option_argument);
        }
        else {
            if (arg[1] == '\0') {
                HandleArgument(&arg_index, arg);
                continue;
            }

            for (int k = 1; arg[k]; ++k) {
                bool matched = false;
                for (const Option &option : options_) {
                    if (option.short_name && arg[k] == option.short_name) {
                        const char *option_argument = nullptr;
                        if (option.has_argument) {
                            if (arg[k + 1] != '\0') {
                                Errorf("option '-%c' requires argument",
                                       option.short_name);
                                break;
                            }

                            if (i + 1 == argc || argv[i + 1][0] == '-') {
                                Errorf("option '-%c' requires argument",
                                       option.short_name);
                                break;
                            }
                            ++i;
                            option_argument = argv[i];
                        }
                        option.callback(option_argument);
                        matched = true;
                        break;
                    }
                }

                if (!matched) {
                    Errorf("unknown option '-%c'", arg[k]);
                    continue;
                }
            }
        }
    }

    if (!arguments_.empty() && arguments_.back().handled_count == 0) {
        for (size_t i = arg_index; i < arguments_.size(); ++i) {
            if (arguments_[i].count != ArgumentCount::ZeroOrMore) {
                Errorf("expected %s argument.", arguments_[i].name.c_str());
            }
        }
    }
}

void
OptionParser::PrintHelp()
{
    printf("usage: %s [options]", program_name_.c_str());

    for (size_t i = 0; i < arguments_.size(); ++i) {
        Argument &argument = arguments_[i];
        switch (argument.count) {
            case ArgumentCount::One:
                printf(" %s", argument.name.c_str());
                break;

            case ArgumentCount::OneOrMore:
                printf(" %s+", argument.name.c_str());
                break;

            case ArgumentCount::ZeroOrMore:
                printf(" [%s]...", argument.name.c_str());
                break;
        }
    }

    printf("\n\n");
    printf("%s\n", description_.c_str());
    printf("options:\n");

    const size_t kExtraSpace = 8;
    size_t longest_name_length = 0;
    for (const Option &option : options_) {
        size_t length;
        if (!option.long_name.empty()) {
            length = option.long_name.size();
            if (!option.metavar.empty()) {
                length += option.metavar.size() + 1;
            }
        }
        else {
            continue;
        }

        if (length > longest_name_length) {
            longest_name_length = length;
        }
    }

    for (const Option &option : options_) {
        if (!option.short_name && option.long_name.empty()) {
            continue;
        }

        std::string line;
        if (option.short_name) {
            line += std::string("  -") + option.short_name + ", ";
        }
        else {
            line += "      ";
        }

        std::string flag;
        if (!option.long_name.empty()) {
            flag = "--";
            if (!option.metavar.empty()) {
                flag += option.long_name + '=' + option.metavar;
            }
            else {
                flag += option.long_name;
            }
        }

        size_t remaining = longest_name_length + kExtraSpace + 2 - flag.size();
        line += flag + std::string(remaining, ' ');

        if (!option.help.empty()) {
            line += option.help;
        }
        printf("%s\n", line.c_str());
    }
}

} // namespace analyzer
