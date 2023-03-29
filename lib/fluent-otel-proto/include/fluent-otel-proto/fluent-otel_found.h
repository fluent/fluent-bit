/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2022 The Fluent Bit Authors
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
 * fluent-otel-proto headers are found in their path.
 *
 * In order to use it, the caller might try to use check_c_source_compiles() CMake function
 * and try to include this header and invoke the inline function defined here, e.g:
 *
 *   check_c_source_compiles("
 *     include <fluent-otel-proto/fluent-otel_found.h>
 *
 *     int main() {
 *        return fluent_otel_found();
 *     }" CFL_FOUND)
 */

#ifndef FLUENT_OTEL_FOUND_H
#define FLUENT_OTEL_FOUND_H

static inline int fluent_otel_found()
{
    return 0;
}

#endif
