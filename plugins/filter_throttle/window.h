/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#define NOT_FOUND -1

struct throttle_pane {
    long timestamp;
    long counter;
};

struct throttle_window {
    long current_timestamp;
    unsigned size;
    unsigned total;
    pthread_mutex_t result_mutex;
    int max_index;
    struct throttle_pane *table;
};

struct throttle_window *window_create(size_t size);
int window_add(struct throttle_window *tw, long timestamp, int val);
