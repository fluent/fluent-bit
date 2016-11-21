/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glob.h>

#include <fluent-bit/flb_input.h>

#include "tail.h"
#include "tail_file.h"
#include "tail_config.h"

/* Scan a path, register the entries and return how many */
int flb_tail_scan(const char *path, struct flb_tail_config *config)
{
    int i;
    int ret;
    glob_t globbuf;
    struct stat st;
    flb_debug("[in_tail] scanning path %s", path);

    /* Scan the given path */
    ret = glob(path, GLOB_TILDE, NULL, &globbuf);
    if (ret != 0) {
        switch (ret) {
        case GLOB_NOSPACE:
            flb_error("[in_tail] no memory space available");
            return -1;
        case GLOB_ABORTED:
            flb_error("[in_tail] read error (GLOB_ABORTED");
            return -1;
        case GLOB_NOMATCH:
            return 0;
        }
    }

    /* For every entry found, generate an output list */
    for (i = 0; i < globbuf.gl_pathc; i++) {
        ret = stat(globbuf.gl_pathv[i], &st);
        if (ret == 0 && S_ISREG(st.st_mode)) {
            flb_tail_file_append(globbuf.gl_pathv[i], &st,
                                 FLB_TAIL_STATIC, config);
        }
        else {
            flb_debug("[in_tail] skip (invalid) entry=%s", globbuf.gl_pathv[i]);
        }
    }

    if (globbuf.gl_pathc > 0) {
        globfree(&globbuf);
    }

    return i;
}
