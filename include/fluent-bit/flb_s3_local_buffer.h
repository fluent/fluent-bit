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

#ifdef FLB_HAVE_AWS

#ifndef flb_local_buffer_H
#define flb_local_buffer_H

struct flb_local_chunk {
    /* identifies this chunk in the buffer dir; created with simple_hash fn */
    flb_sds_t key;
    /* the original fluent tag for this data */
    flb_sds_t tag;
    flb_sds_t file_path;
    size_t size;
    struct timespec ts;
    time_t create_time;

    /* times this chunk could not be sent */
    int failures;

    struct mk_list _head;
};

struct flb_local_buffer {
    char *dir;
    struct flb_output_instance *ins;

    struct mk_list chunks;
};

/*
 * "Initializes" the local buffer from the file system
 * Reads buffer directory and finds any existing files
 * This ensures the plugin will still send buffered data even if FB is restarted
 */
int flb_init_local_buffer(struct flb_local_buffer *store);

/*
 * Stores data in the local file system
 * 'c' should be NULL if no local chunk suitable for this data has been created yet
 */
int flb_buffer_put(struct flb_local_buffer *store, struct flb_local_chunk *c,
                   const char *tag, char *data, size_t bytes);

/*
 * Returns the chunk associated with the given tag
 */
struct flb_local_chunk *flb_chunk_get(struct flb_local_buffer *store, const char *tag);

/*
 * Recursively creates directories
 */
int flb_mkdir_all(const char *dir);

/* Removes all files associated with a chunk once it has been removed */
int flb_remove_chunk_files(struct flb_local_chunk *c);

void flb_chunk_destroy(struct flb_local_chunk *c);

void flb_local_buffer_destroy_chunks(struct flb_local_buffer *store);

#endif
#endif /* FLB_HAVE_AWS */
