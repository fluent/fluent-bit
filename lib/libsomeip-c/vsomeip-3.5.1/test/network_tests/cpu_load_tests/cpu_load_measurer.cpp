// Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "cpu_load_measurer.hpp"

#include <fstream>
#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <stdexcept>
#include <cstdio>

#include <sys/types.h>
#include <unistd.h>

cpu_load_measurer::~cpu_load_measurer() {
}

cpu_load_measurer::cpu_load_measurer(std::uint32_t _pid) :
    pid_(_pid),
    jiffies_complete_start_(0),
    jiffies_idle_start_(0),
    jiffies_complete_stop_(0),
    jiffies_idle_stop_(0),
    clock_ticks_(0),
    jiffies_passed_pid_start_(0),
    jiffies_passed_pid_stop_(0),
    cpu_load_pid_(0.0),
    cpu_load_overall_(0.0),
    cpu_load_pid_wo_idle_(0.0) {
}

void cpu_load_measurer::start() {
    // reset everything
    jiffies_complete_start_ = 0;
    jiffies_idle_start_ = 0;
    jiffies_complete_stop_ = 0;
    jiffies_idle_stop_ = 0;
    clock_ticks_ = 0;
    jiffies_passed_pid_start_ = 0;
    jiffies_passed_pid_stop_ = 0;
    cpu_load_pid_= 0.0;
    cpu_load_overall_ = 0.0;
    cpu_load_pid_wo_idle_ = 0.0;
    //start
    jiffies_complete_start_ = read_proc_stat(&jiffies_idle_start_);
    jiffies_passed_pid_start_ = read_proc_pid_stat();
}

void cpu_load_measurer::stop() {
    jiffies_complete_stop_ = read_proc_stat(&jiffies_idle_stop_);
    jiffies_passed_pid_stop_ = read_proc_pid_stat();
    if(jiffies_complete_stop_ < jiffies_complete_start_ || jiffies_passed_pid_stop_ < jiffies_passed_pid_start_) {
        std::cerr << "Overflow of values in procfs occured, can't calculate load" << std::endl;
        exit(0);
    }
    cpu_load_pid_ = 100.0
            * static_cast<double>(jiffies_passed_pid_stop_
                    - jiffies_passed_pid_start_)
            / static_cast<double>(jiffies_complete_stop_
                    - jiffies_complete_start_);
    cpu_load_overall_ = 100.0
            * static_cast<double>((jiffies_complete_stop_ - jiffies_idle_stop_)
                    - (jiffies_complete_start_ - jiffies_idle_start_))
            / static_cast<double>(jiffies_complete_stop_
                    - jiffies_complete_start_);
    cpu_load_pid_wo_idle_ = 100.0
            * static_cast<double>(jiffies_passed_pid_stop_
                    - jiffies_passed_pid_start_)
            / static_cast<double>((jiffies_complete_stop_ - jiffies_idle_stop_)
                    - (jiffies_complete_start_ - jiffies_idle_start_));

}

void cpu_load_measurer::print_cpu_load() const {
    std::cout << "Used Jiffies complete: "
            << jiffies_complete_stop_ - jiffies_complete_start_ << " (worked: "
            << (jiffies_complete_stop_ - jiffies_idle_stop_)
                    - (jiffies_complete_start_ - jiffies_idle_start_)
            << " idled: " << jiffies_idle_stop_ - jiffies_idle_start_
            << ")" << std::endl;
    std::cout << "Used Jiffies of pid " << pid_ << ": " << jiffies_passed_pid_stop_ - jiffies_passed_pid_start_ << std::endl;
    std::cout << "Cpu load pid " << pid_ << " [%]: " << cpu_load_pid_ << std::endl;
    std::cout << "Overall cpu load[%]: " << cpu_load_overall_ << std::endl;
    std::cout << "Load caused by pid " << pid_ << " of overall cpu load [%]:" << cpu_load_pid_wo_idle_ << std::endl;
}

double cpu_load_measurer::get_cpu_load() const {
    return cpu_load_pid_;
}

std::uint64_t cpu_load_measurer::read_proc_pid_stat() {
    std::string path("/proc/" + std::to_string(pid_) + "/stat");
    FILE* f = std::fopen(path.c_str(), "r");
    if(!f) {
            std::perror(std::string("Failed to open " + path).c_str());
            exit(1);
    }
    // see Table 1-4 Contents of the stat files (as of 2.6.30-rc7)
    // at https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/Documentation/filesystems/proc.txt?id=refs/tags/v3.10.98
    // and man proc (for conversion specifier)
    std::uint64_t utime(0);
    std::uint64_t stime(0);
    std::int64_t cutime(0);
    std::int64_t cstime(0);
    if (std::fscanf(f, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u "
            "%lu %lu %ld %ld", // utime, stime, cutime, cstime
            &utime, &stime, &cutime, &cstime) == EOF) {
        std::cerr << "Failed to read " + path << std::endl;
        exit(1);
    }
    std::fclose(f);
    return utime + stime + static_cast<std::uint64_t>(cutime) +
            static_cast<std::uint64_t>(cstime);
}

std::uint64_t cpu_load_measurer::read_proc_stat(std::uint64_t* _idle) {
    FILE* f = std::fopen("/proc/stat", "r");
    if(!f) {
            std::perror("Failed to open /proc/stat");
            exit(1);
    }

    // see 1.8 Miscellaneous kernel statistics in /proc/stat
    // at https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/Documentation/filesystems/proc.txt?id=refs/tags/v3.10.98
    std::uint64_t user(0);
    std::uint64_t nice(0);
    std::uint64_t system(0);
    std::uint64_t idle(0);
    std::uint64_t iowait(0);
    std::uint64_t irq(0);
    std::uint64_t softirq(0);
    std::uint64_t steal(0);
    std::uint64_t guest(0);
    std::uint64_t guest_nice(0);
    if (std::fscanf(f, "%*s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu", &user,
            &nice, &system, &idle, &iowait, &irq, &softirq, &steal, &guest,
            &guest_nice) == EOF) {
        std::cerr << "Failed to read /proc/stat" << std::endl;
        exit(1);
    }
    std::fclose(f);
    *_idle = idle;
    return user + nice + system + idle + iowait + irq + softirq + steal + guest
    + guest_nice;
}

bool cpu_load_measurer::read_clock_ticks() {
    long val(::sysconf(_SC_CLK_TCK));
    if(val < 0 && errno == EINVAL) {
        std::perror(__func__);
        return false;
    }
    clock_ticks_ = static_cast<std::uint64_t>(val);
    return true;
}
