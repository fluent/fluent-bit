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

#include <fluent-bit/flb_input.h>
#include "tail_config.h"
#include "tail_file.h"

int flb_tail_file_append(char *path, struct flb_tail_config *config)
{

    struct flb_tail_file *file;


    file = flb_malloc(sizeof(struct flb_tail_file));
    if (!file) {
        flb_errno();
        return -1;
    }

    file->name = flb_strdup(path);
    mk_list_add(&file->_head, &config->files);

    flb_debug("[in_tail] add to scan queue %s", path);
    return 0;
}
