/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_s3_local_buffer.h>
#include <monkey/mk_core/mk_list.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>

/*
 * Simple and fast hashing algorithm to create keys in the local buffer
 */
flb_sds_t simple_hash(char *str);

static char *read_tag(char *buffer_path);

void flb_chunk_destroy(struct flb_local_chunk *c)
{
    if (!c) {
        return;
    }
    if (c->key) {
        flb_sds_destroy(c->key);
    }
    if (c->file_path) {
        flb_sds_destroy(c->file_path);
    }
    if (c->tag) {
        flb_sds_destroy(c->tag);
    }
    flb_free(c);
}

void flb_local_buffer_destroy(struct flb_local_buffer *store)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_local_chunk *chunk;

    if (!store) {
        return;
    }
    if (mk_list_is_set(&store->chunks) == 0) {
        mk_list_foreach_safe(head, tmp, &store->chunks) {
            chunk = mk_list_entry(head, struct flb_local_chunk, _head);
            flb_chunk_destroy(chunk);
        }
    }
    flb_free(store);
}

static int is_tag_file(char *string)
{
    string = strrchr(string, '.');

    if (string != NULL) {
        return (strcmp(string, ".tag"));
    }

  return -1;
}

/*
 * "Initializes" the local buffer from the file system
 * Reads buffer directory and finds any existing files
 * This ensures the plugin will still send buffered data even if FB is restarted
 */
int flb_init_local_buffer(struct flb_local_buffer *store)
{
    DIR *d;
    struct dirent *dir;
    struct flb_local_chunk *c;
    char *tag;
    flb_sds_t path;
    flb_sds_t tmp_sds;

    d = opendir(store->dir);
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (dir->d_type == DT_REG) {
                if (strlen(dir->d_name) > 0 && dir->d_name[0] == '.') {
                    /* ignore hidden files */
                    continue;
                }
                if (is_tag_file(dir->d_name) == 0) {
                    continue;
                }
                /* create a new chunk */
                flb_plg_debug(store->ins, "Found existing local buffer file %s",
                              dir->d_name);
                c = flb_calloc(1, sizeof(struct flb_local_chunk));
                if (!c) {
                    flb_errno();
                    return -1;
                }
                c->create_time = time(NULL);
                c->key = flb_sds_create(dir->d_name);
                if (!c->key) {
                    flb_errno();
                    flb_chunk_destroy(c);
                    return -1;
                }
                path = flb_sds_create_size(strlen(store->dir) + strlen(dir->d_name));
                if (!path) {
                    flb_errno();
                    flb_chunk_destroy(c);
                    flb_errno();
                    return -1;
                }
                tmp_sds = flb_sds_printf(&path, "%s/%s", store->dir, dir->d_name);
                if (!tmp_sds) {
                    flb_errno();
                    flb_chunk_destroy(c);
                    flb_sds_destroy(path);
                    return -1;
                }
                path = tmp_sds;
                c->file_path = path;
                /* get the fluent tag */
                tag = read_tag(path);
                if (!tag) {
                    flb_plg_error(store->ins, "Could not read Fluent tag from file system; file path=%s.tag",
                                  path);
                    flb_errno();
                    flb_chunk_destroy(c);
                    return -1;
                }
                c->tag = flb_sds_create(tag);
                flb_free(tag);
                if (!c->tag) {
                    flb_errno();
                    flb_chunk_destroy(c);
                    return -1;
                }
                flb_plg_info(store->ins, "Found existing local buffer %s",
                             path);
                mk_list_add(&c->_head, &store->chunks);
            }
        }
        closedir(d);
    }
    else {
        flb_errno();
        flb_plg_error(store->ins, "Could not open buffer dir %s", store->dir);
    }
    return 0;
}

/*
 * Recursively creates directories
 */
int flb_mkdir_all(const char *dir) {
    char tmp[PATH_MAX];
    char *p = NULL;
    int ret;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);
    if(tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }
    for(p = tmp + 1; *p; p++) {
        if(*p == '/') {
            *p = 0;
            ret = mkdir(tmp, S_IRWXU);
            if (ret < 0 && errno != EEXIST) {
                flb_errno();
                return -1;
            }
            *p = '/';
        }
    }
    ret = mkdir(tmp, S_IRWXU);
    if (ret < 0 && errno != EEXIST) {
        flb_errno();
        return -1;
    }

    return 0;
}

static size_t append_data(char *path, char *data, size_t bytes)
{
    FILE *f;
    size_t written;
    f = fopen(path , "a" );
    if (!f) {
        return -1;
    }
    written = fwrite(data, 1, bytes, f);
    fclose(f);
    return written;
}

/* we store the Fluent tag in a file "<hash_key>.tag" */
static int write_tag(char *buffer_path, char *tag)
{
    char tmp[PATH_MAX];
    size_t ret;

    snprintf(tmp, sizeof(tmp), "%s.tag", buffer_path);
    ret = append_data(tmp, tag, strlen(tag));
    if (ret <= 0) {
        return -1;
    }
    return 0;
}

/* we store the Fluent tag in a file "<hash_key>.tag" */
static char *read_tag(char *buffer_path)
{
    char tmp[PATH_MAX];
    size_t ret;
    char *data;
    size_t data_size;

    snprintf(tmp, sizeof(tmp), "%s.tag", buffer_path);
    ret = flb_read_file(tmp, &data, &data_size);
    if (ret < 0) {
        return NULL;
    }
    return data;
}

/*
 * Stores data in the local file system
 * 'c' should be NULL if no local chunk suitable for this data has been created yet
 */
int flb_buffer_put(struct flb_local_buffer *store, struct flb_local_chunk *c,
                   char *tag, char *data, size_t bytes)
{
    size_t written;
    flb_sds_t path;
    flb_sds_t tmp_sds;
    flb_sds_t hash_key;
    int ret;

    hash_key = simple_hash(tag);
    if (!hash_key) {
        flb_plg_error(store->ins, "Could not create local buffer hash key for %s",
                      tag);
        return -1;
    }

    if (c == NULL) {
        /* create a new chunk */
        flb_plg_debug(store->ins, "Creating new local buffer for %s", tag);
        c = flb_calloc(1, sizeof(struct flb_local_chunk));
        if (!c) {
            flb_sds_destroy(hash_key);
            flb_errno();
            return -1;
        }
        c->create_time = time(NULL);
        c->key = flb_sds_create(hash_key);
        if (!c->key) {
            flb_errno();
            flb_sds_destroy(hash_key);
            flb_chunk_destroy(c);
            return -1;
        }
        c->tag = flb_sds_create(tag);
        if (!c->tag) {
            flb_errno();
            flb_sds_destroy(hash_key);
            flb_chunk_destroy(c);
            return -1;
        }
        path = flb_sds_create_size(strlen(store->dir) + strlen(hash_key));
        if (!path) {
            flb_errno();
            flb_sds_destroy(hash_key);
            flb_chunk_destroy(c);
            flb_errno();
            return -1;
        }
        tmp_sds = flb_sds_printf(&path, "%s/%s", store->dir, hash_key);
        if (!tmp_sds) {
            flb_errno();
            flb_sds_destroy(hash_key);
            flb_chunk_destroy(c);
            flb_sds_destroy(path);
            return -1;
        }
        path = tmp_sds;
        c->file_path = path;
        /* save the fluent tag */
        ret = write_tag(path, tag);
        if (ret < 0) {
            flb_plg_error(store->ins, "Could not save Fluent tag to file system; buffer dir=%s",
                          store->dir);
        }
        mk_list_add(&c->_head, &store->chunks);
    }

    flb_sds_destroy(hash_key);

    written = append_data(c->file_path, data, bytes);
    if (written > 0) {
        c->size += written;
    }
    if (written < bytes) {
        flb_plg_error(store->ins, "Failed to write %d bytes to local buffer %s",
                      bytes - written, path);
        flb_errno();
        return -1;
    }

    flb_plg_debug(store->ins, "Buffered %d bytes", bytes);
    return 0;
}



/*
 * Returns the chunk associated with the given key
 */
struct flb_local_chunk *flb_chunk_get(struct flb_local_buffer *store, char *tag)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_local_chunk *c = NULL;
    struct flb_local_chunk *tmp_chunk;
    flb_sds_t hash_key;

    hash_key = simple_hash(tag);
    if (!hash_key) {
        flb_plg_error(store->ins, "Could not create local buffer hash key for tag %s",
                      tag);
        return NULL;
    }

    mk_list_foreach_safe(head, tmp, &store->chunks) {
        tmp_chunk = mk_list_entry(head, struct flb_local_chunk, _head);
        if (strcmp(tmp_chunk->key, hash_key) == 0) {
            c = tmp_chunk;
            break;
        }
    }

    flb_sds_destroy(hash_key);
    return c;
}

/*
 * Simple and fast hashing algorithm to create keys in the local buffer
 */
flb_sds_t simple_hash(char *str)
{
    unsigned long hash = 5381;
    int c;
    flb_sds_t hash_str;
    flb_sds_t tmp;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    /* flb_sds_printf allocs if the incoming sds is not at least 64 bytes */
    hash_str = flb_sds_create_size(64);
    if (!hash_str) {
        flb_errno();
        return NULL;
    }
    tmp = flb_sds_printf(&hash_str, "%lu", hash);
    if (!tmp) {
        flb_errno();
        flb_sds_destroy(hash_str);
        return NULL;
    }
    hash_str = tmp;

    return hash_str;
}

/* Removes all files associated with a chunk once it has been removed */
int flb_remove_chunk_files(struct flb_local_chunk *c)
{
    int ret;
    char tmp[PATH_MAX];

    ret = remove(c->file_path);
    if (ret < 0) {
        flb_errno();
        return ret;
    }

    snprintf(tmp, sizeof(tmp), "%s.tag", c->file_path);
    ret = remove(tmp);
    if (ret < 0) {
        flb_errno();
    }
    return ret;
}