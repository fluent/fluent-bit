/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P. <edsiper@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>

#include "mk_macros.h"
#include "mk_string.h"

/*
 * Base function for search routines, it accept modifiers to enable/disable
 * the case sensitive feature and also allow to specify a haystack len
 * Get position of a substring.
*/
static int _mk_string_search(const char *string, const char *search,
                             int sensitive, int len)
{
    int i = 0;
    char *p = NULL, *q = NULL;
    char *s = NULL;

    /* Fast path */
    if (len <= 0) {
        switch(sensitive) {
        case MK_STR_SENSITIVE:
            p = strstr(string, search);
            break;
        case MK_STR_INSENSITIVE:
            p = strcasestr(string, search);
            break;
        }

        if (p) {
            return (p - string);
        }
        else {
            return -1;
        }
    }

    p = (char *) string;
    do {
        q = p;
        s = (char *) search;
        if (sensitive == MK_STR_SENSITIVE) {
            while (*s && (*s == *q)) {
                q++, s++;
            }
        }
        else if (sensitive == MK_STR_INSENSITIVE) {
            while (*s && (toupper(*q) == toupper(*s))) {
                q++, s++;
            }
        }

        /* match */
        if (*s == 0) {
            return (p - string);
        }

        i++;
        if (i >= len) {
            break;
        }
    } while (*p++);

    return -1;
}

/* Lookup char into string, return position */
int mk_string_char_search(const char *string, int c, int len)
{
    char *p;

    if (len < 0) {
        len = strlen(string);
    }

    p = memchr(string, c, len);
    if (p) {
        return (p - string);
    }

    return -1;
}

/* Find char into string searching in reverse order, returns position */
int mk_string_char_search_r(const char *string, int c, int len)
{
    char *p;

    if (len <= 0) {
        len = strlen(string);
    }

    p = memrchr(string, c, len);
    if (p) {
        return (p - string);
    }

    return -1;
}

int mk_string_search(const char *haystack, const char *needle, int sensitive)
{
    return _mk_string_search(haystack, needle, sensitive, -1);
}

int mk_string_search_n(const char *haystack, const char *needle, int sensitive, int len)
{
    return _mk_string_search(haystack, needle, sensitive, len);
}

char *mk_string_casestr(char *heystack, char *needle)
{
    if (!heystack || !needle) {
        return NULL;
    }

    return strcasestr(heystack, needle);
}

char *mk_string_dup(const char *s)
{
    size_t len;
    char *p;

    if (!s)
        return NULL;

    len = strlen(s);
    p = malloc(len + 1);
    memcpy(p, s, len);
    p[len] = '\0';

    return p;
}

struct mk_list *mk_string_split_line(const char *line)
{
    unsigned int i = 0, len, val_len;
    int end;
    char *val;
    struct mk_list *list;
    struct mk_string_line *new;

    if (!line) {
        return NULL;
    }

    list = malloc(sizeof(struct mk_list));
    mk_list_init(list);

    len = strlen(line);

    while (i < len) {
        end = mk_string_char_search(line + i, ' ', len - i);

        if (end >= 0 && end + i < len) {
            end += i;

            if (i == (unsigned int) end) {
                i++;
                continue;
            }

            val = mk_string_copy_substr(line, i, end);
            val_len = end - i;
        }
        else {
            val = mk_string_copy_substr(line, i, len);
            val_len = len - i;
            end = len;

        }

        /* Alloc node */
        new = malloc(sizeof(struct mk_string_line));
        new->val = val;
        new->len = val_len;

        mk_list_add(&new->_head, list);
        i = end + 1;
    }

    return list;
}

void mk_string_split_free(struct mk_list *list)
{
    struct mk_list *head, *tmp;
    struct mk_string_line *entry;

    mk_list_foreach_safe(head, tmp, list) {
        entry = mk_list_entry(head, struct mk_string_line, _head);
        mk_list_del(&entry->_head);
        mk_mem_free(entry->val);
        mk_mem_free(entry);
    }

    mk_mem_free(list);
}

char *mk_string_build(char **buffer, unsigned long *len,
                      const char *format, ...)
{
    va_list ap;
    int length;
    char *ptr;
    const size_t _mem_alloc = 64;
    size_t alloc = 0;

    /* *buffer *must* be an empty/NULL buffer */
    *buffer = (char *) malloc(_mem_alloc);

    if (!*buffer) {
        return NULL;
    }
    alloc = _mem_alloc;

    va_start(ap, format);
    length = vsnprintf(*buffer, alloc, format, ap);
    va_end(ap);

    if (length < 0) {
        return NULL;
    }

    if ((unsigned int) length >= alloc) {
        ptr = realloc(*buffer, length + 1);
        if (!ptr) {
            return NULL;
        }
        *buffer = ptr;
        alloc = length + 1;

        va_start(ap, format);
        length = vsnprintf(*buffer, alloc, format, ap);
        va_end(ap);
    }

    ptr = *buffer;
    ptr[length] = '\0';
    *len = length;

    return *buffer;
}

int mk_string_trim(char **str)
{
    unsigned int i;
    unsigned int len;
    char *left = 0, *right = 0;
    char *buf;

    buf = *str;
    if (!buf) {
        return -1;
    }

    len = strlen(buf);
    left = buf;

    if(len == 0) {
        return 0;
    }

    /* left spaces */
    while (left) {
        if (isspace(*left)) {
            left++;
        }
        else {
            break;
        }
    }

    right = buf + (len - 1);
    /* Validate right v/s left */
    if (right < left) {
        buf[0] = '\0';
        return -1;
    }

    /* Move back */
    while (right != buf){
        if (isspace(*right)) {
            right--;
        }
        else {
            break;
        }
    }

    len = (right - left) + 1;
    for(i=0; i<len; i++){
        buf[i] = (char) left[i];
    }
    buf[i] = '\0';

    return 0;
}

/* Return a buffer with a new string from string */
char *mk_string_copy_substr(const char *string, int pos_init, int pos_end)
{
    unsigned int size, bytes;
    char *buffer = 0;

    if (pos_init > pos_end) {
        return NULL;
    }

    size = (unsigned int) (pos_end - pos_init) + 1;
    if (size <= 2)
        size = 4;

    buffer = malloc(size);

    if (!buffer) {
        return NULL;
    }

    bytes = pos_end - pos_init;
    memcpy(buffer, string + pos_init, bytes);
    buffer[bytes] = '\0';

    return (char *) buffer;
}

char *mk_string_tolower(const char *in)
{
    char *out = mk_string_dup(in);
    const char *ip = in;
    char *op = out;

    while (*ip) {
        *op = tolower(*ip);
        ip++, op++;
    }
    *op = '\0';

    return out;
}
