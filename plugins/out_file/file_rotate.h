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

#ifndef FLB_OUT_FILE_ROTATE_H
#define FLB_OUT_FILE_ROTATE_H

#include <fluent-bit/flb_output_plugin.h>

#include <stdio.h>

struct file_rotate_ctx;
struct file_rotate_entry;

/*
 * Create the rotation context. When 'enabled' is FLB_FALSE the context is
 * inert and file_rotate_acquire() reports success without tracking anything.
 * Returns NULL on invalid configuration or allocation failure.
 */
struct file_rotate_ctx *file_rotate_create(struct flb_output_instance *ins,
                                           int enabled, size_t max_size,
                                           int max_files, int gzip);

void file_rotate_destroy(struct file_rotate_ctx *rot);

/*
 * Take ownership of 'path' for the duration of a write, rotating it first when
 * its recorded size has reached the configured limit. On success returns 0 with
 * the entry lock held, and the caller must pair it with file_rotate_release().
 * On an inert context '*entry' is set to NULL and 0 is returned.
 */
int file_rotate_acquire(struct file_rotate_ctx *rot, const char *path,
                        struct file_rotate_entry **entry);

/* Refresh the recorded size after writing. Ignores a NULL entry. */
void file_rotate_update(struct file_rotate_entry *entry, FILE *fp);

/* Release the lock taken by file_rotate_acquire(). Ignores a NULL entry. */
void file_rotate_release(struct file_rotate_entry *entry);

#endif
