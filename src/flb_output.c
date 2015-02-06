/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_config.h>

#define protcmp(a, b)  strncasecmp(a, b, strlen(a))

/* Copy a sub-string in a new memory buffer */
static char *copy_substr(char *str, int s)
{
    char *buf;

    buf = malloc(s + 1);
    strncpy(buf, str, s);
    buf[s] = '\0';

    return buf;
}


/*
 * It parse the out_address, split the hostname, port (if any)
 * or set the default port based on the matched protocol
 */
static int split_address(struct flb_config *config)
{
    int len;
    char *sep;
    char *tmp;

    if (config->out_protocol == FLB_OUTPUT_FLUENT) {
        tmp = config->out_address + FLB_OUTPUT_FLUENT_Z;
        sep = strchr(tmp, ':');

        if (sep == tmp) {
            return -1;
        }

        if (sep) {
            len = (sep - tmp);
            config->out_host = copy_substr(tmp, sep - tmp);

            tmp += len + 1;
            len = strlen(tmp);
            if (len == 0) {
                config->out_port = strdup(FLB_OUTPUT_FLUENT_PORT);
                return 0;
            }
            config->out_port = copy_substr(tmp, len);
        }
        else {
            if (strlen(tmp) == 0) {
                printf("?\n");
                return -1;
            }

            config->out_host = strdup(tmp);
            config->out_port = strdup(FLB_OUTPUT_FLUENT_PORT);
            return 0;
        }
    }

    return 0;
}

/* Validate the the output address protocol */
static int check_protocol(char *prot, char *output)
{
    int len = strlen(prot);

    if (strlen(prot) > strlen(output)) {
        return 0;
    }

    if (protcmp(prot, output) != 0) {
        return 0;
    }

    if (output[len] != ':' ||
        output[len + 1] != '/' ||
        output[len + 1] != '/') {
        return 0;
    }

    return 1;
}

/*
 * It validate an output type given the string, it return the
 * proper type and if valid, populate the global config.
 */
int flb_output_check(struct flb_config *config, char *output)
{
    int ret = -1;

    if (!output) {
        return -1;
    }

    config->out_address = output;

    /* Fluentd */
    if (check_protocol("fluentd", output)) {
        config->out_protocol = FLB_OUTPUT_FLUENT;
        ret = split_address(config);
    }

    return ret;
}
