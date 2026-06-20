/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_slist.h>
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
    sprintf(filename, "/tmp/libfuzzer.%d", getpid());
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        return 0;
    }
    fwrite(data, size, 1, fp);
    fclose(fp);

    /* Now parse a random config file */
    struct flb_config *config = NULL;
    config = flb_config_init();
    flb_parser_conf_file(filename, config);
    flb_parser_exit(config);
    flb_config_exit(config);

    /* Cleanup written config file */
    unlink(filename);

    return 0;
}
