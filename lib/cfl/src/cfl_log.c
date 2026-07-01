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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cfl/cfl_log.h>

#ifdef _WIN32
    #define strerror_r(errnum, buf, buf_size) strerror_s(buf, buf_size, errnum)
#endif

int cfl_report_runtime_error_impl(int errnum, char *file, int line)
{
    char buf[256];

    strerror_r(errnum, buf, sizeof(buf) - 1);

    fprintf(stderr, "[%s:%i errno=%i] %s\n",
            file, line, errnum, buf);

    return 0;
}
