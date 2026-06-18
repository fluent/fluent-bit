/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2022 The CFL Authors
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

#include <cfl/cfl_array.h>
#include <cfl/cfl_atomic.h>
#include <cfl/cfl_checksum.h>
#include <cfl/cfl_compat.h>
#include <cfl/cfl_found.h>
#include <cfl/cfl_hash.h>
#include <cfl/cfl_info.h>
#include <cfl/cfl_kv.h>
#include <cfl/cfl_kvlist.h>
#include <cfl/cfl_list.h>
#include <cfl/cfl_log.h>
#include <cfl/cfl_object.h>
#include <cfl/cfl_sds.h>
#include <cfl/cfl_time.h>
#include <cfl/cfl_utils.h>
#include <cfl/cfl_variant.h>
#include <cfl/cfl_version.h>
#include <cfl/cfl.h>

#include "cfl_tests_internal.h"

static void public_headers_compile()
{
    TEST_CHECK(cfl_found() == 0);
}

TEST_LIST = {
    {"public_headers_compile", public_headers_compile},
    { 0 }
};
