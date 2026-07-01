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

#ifndef IN_BLOB_FILE_H
#define IN_BLOB_FILE_H

#include <fluent-bit/flb_input_plugin.h>

#include "blob.h"

int blob_file_append(struct blob_ctx *ctx, char *path, struct stat *st);
void blob_file_list_remove(struct blob_file *bfile);
void blob_file_list_remove_all(struct blob_ctx *ctx);

#endif