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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_slist.h>

/* Initialize slist */
int flb_slist_create(struct mk_list *list)
{
    mk_list_init(list);
    return 0;
}

/* Append 'len' bytes of 'str' as a new string node into the list */
int flb_slist_add_n(struct mk_list *head, const char *str, int len)
{
    struct flb_slist_entry *e;

    e = flb_malloc(sizeof(struct flb_slist_entry));
    if (!e) {
        flb_errno();
        return -1;
    }

    e->str = flb_sds_create_len(str, len);
    if (!e->str) {
        flb_free(e);
        return -1;
    }

    mk_list_add(&e->_head, head);
    return 0;
}

int flb_slist_add_sds(struct mk_list *head, flb_sds_t str)
{
    struct flb_slist_entry *e;

    e = flb_malloc(sizeof(struct flb_slist_entry));
    if (!e) {
        flb_errno();
        return -1;
    }

    e->str = str;
    mk_list_add(&e->_head, head);
    return 0;
}

/* Append NULL terminated string as a new node into the list */
int flb_slist_add(struct mk_list *head, const char *str)
{
    int len;

    if (!str) {
        return -1;
    }

    len = strlen(str);
    if (len <= 0) {
        return -1;
    }

    return flb_slist_add_n(head, str, len);
}

static inline int token_unescape(char *token)
{
    char *in = token;
    char *out = token;

    while (*in) {
        if ((in[0] == '\\') && (in[1] == '"')) {
            *out = in[1];
            out++;
            in += 2;
        }
        else {
            *out = *in;
            out++;
            in++;
        }
    }
    *out = 0;
    return out - token;
}

static flb_sds_t token_retrieve(char **str)
{
    int len;
    int quoted = FLB_FALSE;
    char *p;
    char *start;
    char *prev;
    flb_sds_t out = NULL;

    if (!*str) {
        return NULL;
    }

    p = *str;

    /* Skip empty spaces */
    while (*p == ' ') {
        p++;
    }
    start = p;

    if (*p == '"') {
        quoted = FLB_TRUE;
        p++;
        start = p;
        while (1) {
            while (*p && *p != '"') {
                p++;
            }

            if (!*p) {
                goto exit;
            }

            prev = p - 1;
            if (*prev == '\\') {
                p++;
                continue;
            }
            goto exit;
        }
    }

    while (*p && *p != ' ') {
        p++;
    }

 exit:
    if (*p) {
        out = flb_sds_create_len(start, p - start);
        if (!out) {
            *str = NULL;
            return NULL;
        }
        if (quoted == FLB_TRUE) {
            len = token_unescape(out);
            flb_sds_len_set(out, len);
        }
        p++;

        while (*p && *p == ' ') {
            p++;
        }
        *str = p;
    }
    else {
        if (p > start) {
            out = flb_sds_create(start);
        }
        *str = NULL;
    }

    return out;
}

int flb_slist_split_tokens(struct mk_list *list, const char *str, int max_split)
{
    int count = 0;
    char *p;
    char *buf;
    flb_sds_t tmp = NULL;

    buf = (char *) str;
    while ((tmp = token_retrieve(&buf))) {
        if (flb_slist_add_sds(list, tmp) == -1) {
            flb_sds_destroy(tmp);
            return -1;
        }
        if (!buf) {
            break;
        }
        count++;

        /* Append remaining string if we use a maximum number of tokens */
        if (count >= max_split && max_split > 0) {
            p = buf;
            while (*p == ' ') {
                p++;
            }

            if (*p) {
                if (flb_slist_add(list, p) == -1) {
                    return -1;
                }
            }
            break;
        }
    }

    return 0;
}

/*
 * Split a string using a separator, every splitted content is appended to the end of
 * the slist list head.
 */
int flb_slist_split_string(struct mk_list *list, const char *str,
                           int separator, int max_split)
{
    int i = 0;
    int ret;
    int count = 0;
    int val_len;
    int len;
    int end;
    char *p_init;
    char *p_end;

    if (!str) {
        return -1;
    }

    len = strlen(str);
    while (i < len) {
        end = mk_string_char_search(str + i, separator, len - i);
        if (end < 0) {
            end = len - i;
        }
        else if ((end + i) == i) {
            i++;
            continue;
        }

        p_init = (char *) str + i;
        p_end = p_init + end - 1;

        /* Skip empty spaces */
        while (*p_init == ' ') {
            p_init++;
        }

        while (*p_end == ' ' && p_end >= p_init) {
            p_end--;
        }

        if (p_init > p_end) {
            goto next;
        }

        if (p_init == p_end) {
            if (*p_init == ' ') {
                goto next;
            }
            val_len = 1;
        }
        else {
            val_len = (p_end - p_init) + 1;
        }

        if (val_len == 0) {
            goto next;
        }

        ret = flb_slist_add_n(list, p_init, val_len);
        if (ret == -1) {
            return -1;
        }
        count++;

        /* Append remaining string as a new node ? */
        if (count >= max_split && max_split > 0) {
            p_end = p_init + end;
            if (*p_end == separator) {
                p_end++;
            }
            while (*p_end == ' ') {
                p_end++;
            }

            if ((p_end - str) >= len) {
                break;
            }

            ret = flb_slist_add(list, p_end);
            if (ret == -1) {
                return -1;
            }
            count++;
            break;
        }

    next:
        i += end + 1;
    }

    return count;
}

void flb_slist_dump(struct mk_list *list)
{
    struct mk_list *head;
    struct flb_slist_entry *e;

    printf("[slist %p]\n", list);
    mk_list_foreach(head, list) {
        e = mk_list_entry(head, struct flb_slist_entry, _head);
        printf(" - '%s'\n", e->str);
    }
}

void flb_slist_destroy(struct mk_list *list)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_slist_entry *e;

    mk_list_foreach_safe(head, tmp, list) {
        e = mk_list_entry(head, struct flb_slist_entry, _head);
        flb_sds_destroy(e->str);
        mk_list_del(&e->_head);
        flb_free(e);
    }
}

/* Return the entry in position number 'n' */
struct flb_slist_entry *flb_slist_entry_get(struct mk_list *list, int n)
{
    int i = 0;
    struct mk_list *head;
    struct flb_slist_entry *e;

    if (!list || mk_list_size(list) == 0) {
        return NULL;
    }

    mk_list_foreach(head, list) {
        if (i == n) {
            e = mk_list_entry(head, struct flb_slist_entry, _head);
            return e;
        }
        i++;
    }

    return NULL;
}
