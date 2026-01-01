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

#include <stdlib.h>
#include <monkey/mk_core.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_uri.h>
#include <fluent-bit/flb_utils.h>

/*
 * Perform URI encoding for the given string. Always returns a new sds buffer,
 * if it fails it returns NULL.
 */
flb_sds_t flb_uri_encode(const char *uri, size_t len)
{
    int i;
    flb_sds_t buf = NULL;
    flb_sds_t tmp = NULL;

    buf = flb_sds_create_size(len * 2);
    if (!buf) {
        flb_error("[uri] cannot allocate buffer for URI encoding");
        return NULL;
    }

    for (i = 0; i < len; i++) {
        if (flb_uri_to_encode(uri[i]) == FLB_TRUE) {
            tmp = flb_sds_printf(&buf, "%%%02X", (unsigned char) *(uri + i));
            if (!tmp) {
                flb_error("[uri] error formatting special character");
                flb_sds_destroy(buf);
                return NULL;
            }
            continue;
        }

        /* Direct assignment, just copy the character */
        if (buf) {
            tmp = flb_sds_cat(buf, uri + i, 1);
            if (!tmp) {
                flb_error("[uri] error composing outgoing buffer");
                flb_sds_destroy(buf);
                return NULL;
            }
            buf = tmp;
        }
    }

    return buf;
}

/* Retrieve a given field based on it expected position in the URI */
struct flb_uri_field *flb_uri_get(struct flb_uri *uri, int pos)
{
    if (pos < 0) {
        flb_trace("[uri] negative pos");
        return NULL;
    }

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
struct flb_uri *flb_uri_create(const char *full_uri)
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

    /* Initialize fields list */
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
