/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CProfiles
 *  ========
 *  Copyright 2024 The CProfiles Authors
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

#ifndef CPROF_ENCODE_TEXT_H
#define CPROF_ENCODE_TEXT_H

#include <cprofiles/cprofiles.h>
#include <cfl/cfl_sds.h>

#define CPROF_ENCODE_TEXT_SUCCESS                0
#define CPROF_ENCODE_TEXT_ALLOCATION_ERROR       1
#define CPROF_ENCODE_TEXT_INVALID_ARGUMENT_ERROR 2

#define CPROF_ENCODE_TEXT_RENDER_DICTIONARIES_AND_INDEXES 0
#define CPROF_ENCODE_TEXT_RENDER_RESOLVED                 1

struct cprof_text_encoding_context {
    cfl_sds_t output_buffer;
    size_t    indentation_level;
    cfl_sds_t indentation_buffer;
    size_t    indentation_level_size;
    char      indentation_character;
    int       render_mode;
};

int cprof_encode_text_create(cfl_sds_t *result_buffer,
                             struct cprof *profile,
                             int render_mode);

void cprof_encode_text_destroy(cfl_sds_t instance);

#endif
