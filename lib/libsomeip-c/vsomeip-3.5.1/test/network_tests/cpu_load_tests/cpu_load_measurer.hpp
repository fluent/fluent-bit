// Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <cstdint>

class cpu_load_measurer {
public:
    cpu_load_measurer(std::uint32_t _pid);
    virtual ~cpu_load_measurer();
    void start();
    void stop();
    void print_cpu_load() const;
    double get_cpu_load() const;

private:
    std::uint64_t read_proc_stat(std::uint64_t* _idle);
    std::uint64_t read_proc_pid_stat();
    bool read_clock_ticks();
private:
    std::uint32_t pid_;
    std::uint64_t jiffies_complete_start_;
    std::uint64_t jiffies_idle_start_;
    std::uint64_t jiffies_complete_stop_;
    std::uint64_t jiffies_idle_stop_;
    std::uint64_t clock_ticks_;
    std::uint64_t jiffies_passed_pid_start_;
    std::uint64_t jiffies_passed_pid_stop_;
    double cpu_load_pid_;
    double cpu_load_overall_;
    double cpu_load_pid_wo_idle_;
};
