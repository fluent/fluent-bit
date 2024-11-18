// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "stopwatch.hpp"

#include <cassert>
#include <ctime>


#define USEC_PER_SEC  1000000ULL
#define NSEC_PER_USEC 1000ULL


stop_watch::usec_t stop_watch::get_total_elapsed_microseconds() const {
    usec_t elapsed = total_elapsed_;

    if (started_)
        elapsed += get_elapsed();

    return elapsed;
}

stop_watch::usec_t stop_watch::get_total_elapsed_seconds() const {
    return get_total_elapsed_microseconds() / USEC_PER_SEC;
}

stop_watch::usec_t stop_watch::now() {
    struct timespec ts;

#ifdef __QNX__
    const int ret = clock_gettime(CLOCK_MONOTONIC, &ts);
#else
    const int ret = clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#endif
    assert(!ret);
    static_cast<void>(ret); // prevent warning in release build

    return (usec_t) ts.tv_sec * USEC_PER_SEC + (usec_t) ts.tv_nsec / NSEC_PER_USEC;
}
