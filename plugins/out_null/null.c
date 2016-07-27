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

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <fluent-bit/flb_output.h>

int cb_null_init(struct flb_output_instance *ins,
                 struct flb_config *config,
                 void *data)
{
    (void) ins;
    (void) config;
    (void) data;

    return 0;
}

int cb_null_flush(void *data, size_t bytes,
                  char *tag, int tag_len,
                  struct flb_input_instance *i_ins,
                  void *out_context,
                  struct flb_config *config)
{
    int fd;
    int ret;
    size_t total = 0;
    (void) i_ins;
    (void) tag;
    (void) tag_len;

    fd = open("/dev/null", O_WRONLY);
    if (fd == -1) {
        perror("open");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    while (total < bytes) {
        ret = write(fd, data + total, bytes - total);
        if (ret == -1) {
            perror("write");
            close(fd);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        total += ret;
    }
    close(fd);
    FLB_OUTPUT_RETURN(FLB_OK);
}

struct flb_output_plugin out_null_plugin = {
    .name         = "null",
    .description  = "Flush data to /dev/null",
    .cb_init      = cb_null_init,
    .cb_flush     = cb_null_flush,
    .flags        = 0,
};
