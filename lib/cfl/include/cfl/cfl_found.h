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

/*
 * This is a dummy header that can be used by parent projects to check if
 * CFL headers are found in their path.
 *
 * Why ?, because <cfl/cfl.h> includes "cfl_info.h" which is only generated once
 * CMake runs in CFL project. Likely this check is done before that.
 *
 *
 * In order to use it, the caller might try to use check_c_source_compiles() CMake function
 * and try to include this header and invoke the inline function defined here, e.g:
 *
 *   check_c_source_compiles("
 *     include <cfl/cfl_found.h>
 *
 *     int main() {
 *        return cfl_found();
 *     }" CFL_FOUND)
 */

#ifndef CFL_FOUND_H
#define CFL_FOUND_H

static inline int cfl_found()
{
    return 0;
}

#endif
