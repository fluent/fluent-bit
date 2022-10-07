/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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

#ifndef CMT_TESTS_H
#define CMT_TESTS_H

#include "lib/acutest/acutest.h"

#define MSGPACK_STABILITY_TEST_ITERATION_COUNT   1000
#define MSGPACK_PARTIAL_PROCESSING_ELEMENT_COUNT 20

#include "tests/cmt_tests_config.h"
#include "encode_output.h"

#include <cmetrics/cmetrics.h>

cfl_sds_t read_file(const char *path);

#endif
