/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <stdlib.h>
#include <monkey/mk_core.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_uri.h>
#include <fluent-bit/flb_utils.h>

/* Retrieve a given field based on it expected position in the URI */
struct flb_uri_field *flb_uri_get(struct flb_uri *uri, int pos)
{
    if (pos >= FLB_URI_MAX || pos > uri->count) {
        flb_trace("[uri] requested position > FLB_URI_MAX");
        return NULL;
    }

    return &uri->map[pos];
}

/*
 * Given a 'URI' string, split the strings separated by a slash and create a
 * context.
 */
struct flb_uri *flb_uri_create(char *full_uri)
{
    int end;
    unsigned int len;
    unsigned int val_len;
    unsigned int i = 0;
    char *val;
    size_t uri_size;
    void *p;
    struct flb_uri_field *field;
    struct flb_uri *uri;

    /* Set the required memory space */
    uri_size  = sizeof(struct flb_uri);
    uri_size += (sizeof(struct flb_uri_field) * FLB_URI_MAX);

    p  = flb_calloc(1, uri_size);
    if (!p) {
        perror("malloc");
        return NULL;
    }

    /* Link the 'map' */
    uri = p;
    p = ((char *) p) + sizeof(struct flb_uri);
    uri->map = p;

    /* Initilize fields list */
    mk_list_init(&uri->list);
    uri->count = 0;

    len = strlen(full_uri);
    while (i < len && uri->count < FLB_URI_MAX) {
        end = mk_string_char_search(full_uri + i, '/', len - i);

        if (end >= 0 && end + i < len) {
            end += i;

            if (i == (unsigned int) end) {
                i++;
                continue;
            }

            val = mk_string_copy_substr(full_uri, i, end);
            val_len = end - i;
        }
        else {
            val = mk_string_copy_substr(full_uri, i, len);
            val_len = len - i;
            end = len;

        }

        /* Alloc node */
        field = &uri->map[uri->count];
        field->value         = flb_strdup(val);
        field->length        = val_len;
        mk_list_add(&field->_head, &uri->list);
        i = end + 1;
        uri->count++;

        mk_mem_free(val);
    }

    uri->full = flb_strdup(full_uri);
    return uri;
}

/* Destroy an URI context and it resources associated */
void flb_uri_destroy(struct flb_uri *uri)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_uri_field *field;

    mk_list_foreach_safe(head, tmp, &uri->list) {
        field = mk_list_entry(head, struct flb_uri_field, _head);
        mk_list_del(&field->_head);
        flb_free(field->value);
    }

    flb_free(uri->full);
    flb_free(uri);
}

void flb_uri_dump(struct flb_uri *uri)
{
    int i;
    struct flb_uri_field *f;

    for (i = 0; i < uri->count; i++) {
        f = &uri->map[i];
        printf("[%i] length=%lu value='%s'\n",
               i, f->length, f->value);
    }
}
