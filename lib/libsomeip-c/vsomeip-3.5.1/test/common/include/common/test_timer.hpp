// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef TEST_TIMER_HPP
#define TEST_TIMER_HPP

#include <chrono>

class test_timer_t {
public:
    test_timer_t(std::chrono::milliseconds target_) :
        target(target_), start(std::chrono::high_resolution_clock::now()) { }
    test_timer_t(std::chrono::seconds target_) :
        target(std::chrono::duration_cast<std::chrono::milliseconds>(target_)),
        start(std::chrono::high_resolution_clock::now()) { }

    bool has_elapsed() {
        const auto current = std::chrono::high_resolution_clock::now();
        return target <= std::chrono::duration_cast<std::chrono::seconds>(current - start);
    }

private:
    std::chrono::milliseconds target;
    std::chrono::system_clock::time_point start;
};

#endif // TEST_TIMER_HPP
