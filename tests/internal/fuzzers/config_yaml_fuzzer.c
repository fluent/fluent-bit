/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_config_format.h>

#include <cfl/cfl.h>
#include <cfl/cfl_list.h>

#include "flb_fuzz_header.h"


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Set fuzzer-malloc chance of failure */
    flb_malloc_p = 0;
    flb_malloc_mod = 25000;

    /* Limit the size of the config files to 32KB. */
    if (size > 32768) {
        return 0;
    }

    /* Write the config file to a location we know OSS-Fuzz has */
    char filename[256];
    sprintf(filename, "/tmp/libfuzzer.%d.yaml", getpid());
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        return 0;
    }
    fwrite(data, size, 1, fp);
    fclose(fp);


    struct flb_cf *cf;
    struct flb_cf_section *s;

    cf = flb_cf_yaml_create(NULL, filename, NULL, 0);
    if (cf != NULL) {
        flb_cf_destroy(cf);
    }

    /* clean up the file */
    unlink(filename);

    return 0;
}
