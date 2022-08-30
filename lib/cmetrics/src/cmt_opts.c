/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021 Eduardo Silva <eduardo@calyptia.com>
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

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_opts.h>

/* Initialize an 'opts' context with given values */
int cmt_opts_init(struct cmt_opts *opts,
                  char *ns, char *subsystem, char *name,
                  char *description)
{
    int len;
    cmt_sds_t tmp;

    if (!name) {
        return -1;
    }

    if (ns) {
        opts->ns = cmt_sds_create(ns);
        if (!opts->ns) {
            return -1;
        }

        opts->fqname = cmt_sds_create(ns);
        if (!opts->fqname) {
            return -1;
        }

        if (strlen(ns) > 0) {
            tmp = cmt_sds_cat(opts->fqname, "_", 1);
            if (!tmp) {
                return -1;
            }

            opts->fqname = tmp;
        }
    }

    if (subsystem) {
        opts->subsystem = cmt_sds_create(subsystem);
        if (!opts->subsystem) {
            return -1;
        }

        if (strlen(opts->subsystem) > 0) {
            tmp = cmt_sds_cat(opts->fqname,
                              opts->subsystem, cmt_sds_len(opts->subsystem));
            if (!tmp) {
                return -1;
                }
            opts->fqname = tmp;

            len = cmt_sds_len(opts->fqname);
            if (opts->fqname[len - 1] != '_') {
                tmp = cmt_sds_cat(opts->fqname, "_", 1);
                if (!tmp) {
                    return -1;
                }
                opts->fqname = tmp;
            }
        }
    }

    opts->name = cmt_sds_create(name);
    opts->description = cmt_sds_create(description);

    if (!opts->name || !opts->description) {
        return -1;
    }

    tmp = cmt_sds_cat(opts->fqname, opts->name, cmt_sds_len(opts->name));
    if (!tmp) {
        return -1;
    }
    opts->fqname = tmp;

    return 0;
}

void cmt_opts_exit(struct cmt_opts *opts)
{
    if (opts->ns) {
        cmt_sds_destroy(opts->ns);
    }

    if (opts->subsystem) {
        cmt_sds_destroy(opts->subsystem);
    }

    if (opts->name) {
        cmt_sds_destroy(opts->name);
    }

    if (opts->description) {
        cmt_sds_destroy(opts->description);
    }

    if (opts->fqname) {
        cmt_sds_destroy(opts->fqname);
    }
}
