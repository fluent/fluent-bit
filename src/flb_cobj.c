/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

struct flb_cobj_ra {
    struct flb_cobj *cobj;
    struct flb_record_accessor *ra;
};

struct flb_cobj_ra *flb_cobj_record_accessor_create(char *pattern, int translate_env)
{
    struct flb_cobj_ra *cobj_ra;
    struct flb_record_accessor *ra;

    ra = flb_ra_create(pattern, translate_env);
    if (!ra) {
        return NULL;
    }

    cobj_ra = flb_cobj_create(FLB_COBJ_RA);
    if (!cobj_ra) {
        flb_ra_destroy(ra);
        return NULL;
    }

    cobj_ra->ra = ra;
    return cobj_ra;
}

void flb_cobj_record_accessor_destroy(struct flb_cobj_ra *cobj_ra)
{
    if (!cobj_ra) {
        return;
    }

    flb_ra_destroy(cobj_ra->ra);
    flb_cobj_destroy(cobj_ra->cobj);
    flb_free(cobj_ra);
}
