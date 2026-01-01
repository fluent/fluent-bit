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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_input_profiles.h>
#include <fluent-bit/flb_input_plugin.h>

#include <cprofiles/cprofiles.h>
#include <cprofiles/cprof_encode_msgpack.h>

static int input_profiles_append(struct flb_input_instance *ins,
                                 size_t processor_starting_stage,
                                 const char *tag, size_t tag_len,
                                 struct cprof *profile_context)
{
    int ret;
    cfl_sds_t out_buf;
    int processor_is_active;

    processor_is_active = flb_processor_is_active(ins->processor);
    if (processor_is_active) {
        if (!tag) {
            if (ins->tag && ins->tag_len > 0) {
                tag = ins->tag;
                tag_len = ins->tag_len;
            }
            else {
                tag = ins->name;
                tag_len = strlen(ins->name);
            }
        }

        ret = flb_processor_run(ins->processor,
                                processor_starting_stage,
                                FLB_PROCESSOR_PROFILES,
                                tag, tag_len,
                                (char *) profile_context,
                                0, NULL, NULL);

        if (ret == -1) {
            return -1;
        }
    }

    /* Convert profile context to msgpack */
    ret = cprof_encode_msgpack_create(&out_buf, profile_context);
    if (ret != 0) {
        flb_plg_error(ins, "could not encode profiles");
        return -1;
    }

    /* Append packed profiles */
    ret = flb_input_chunk_append_raw(ins, FLB_INPUT_PROFILES, 0,
                                     tag, tag_len, out_buf, cfl_sds_len(out_buf));

    cprof_encode_msgpack_destroy(out_buf);

    return ret;
}

/* Take a cprofiles context and enqueue it as a Profile chunk */
int flb_input_profiles_append(struct flb_input_instance *ins,
                              const char *tag, size_t tag_len,
                              struct cprof *profiles_context)
{
    return input_profiles_append(ins,
                                 0,
                                 tag, tag_len,
                                 profiles_context);
}

/* Take a cprofiles context and enqueue it as a Profile chunk */
int flb_input_profiles_append_skip_processor_stages(
        struct flb_input_instance *ins,
        size_t processor_starting_stage,
        const char *tag, size_t tag_len,
        struct cprof *profiles_context)
{
    return input_profiles_append(ins,
                                 processor_starting_stage,
                                 tag, tag_len,
                                 profiles_context);
}
