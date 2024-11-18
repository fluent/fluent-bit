// Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef STOP_WATCH_H_
#define STOP_WATCH_H_

#include <cstdint>


class stop_watch
{
public:
    typedef uint64_t usec_t;

    stop_watch() :
                    started_(false),
                    start_time_point_(0),
                    total_elapsed_(0)
    {
    }

    inline void reset()
    {
        started_ = false;
        total_elapsed_ = 0;
    }

    inline void start()
    {
        start_time_point_ = now();
        started_ = true;
    }

    inline void stop()
    {
        total_elapsed_ += get_elapsed();
        started_ = false;
    }

    usec_t get_total_elapsed_microseconds() const;
    usec_t get_total_elapsed_seconds() const;

private:
    inline usec_t get_elapsed() const
    {
        return now() - start_time_point_;
    }

    static usec_t now();

    bool started_;
    usec_t start_time_point_;
    usec_t total_elapsed_;
};

#endif // STOP_WATCH_H_
