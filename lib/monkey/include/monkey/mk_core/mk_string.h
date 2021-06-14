/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#ifndef MK_STR_H
#define MK_STR_H

#include <stdint.h>
#include "mk_core_info.h"
#include "mk_memory.h"
#include "mk_list.h"
#include "mk_macros.h"

#if defined(_WIN32) || defined(_WIN64)
  #define snprintf _snprintf
  #define vsnprintf _vsnprintf
  #define strcasecmp _stricmp
  #define strncasecmp _strnicmp
#endif

/* Case sensitive OFF */
#define MK_STR_SENSITIVE 0

/* Case sensitive ON */
#define MK_STR_INSENSITIVE 1

struct mk_string_line
{
    char *val;
    int len;

    struct mk_list _head;
};

#if !defined(MK_HAVE_MEMRCHR)
void *memrchr(const void *s, int c, size_t n);
#endif

#ifndef MK_HAVE_MEMMEM
void *memmem(const void *haystack, size_t haystacklen,
             const void *needle, size_t needlelen);
#endif

/* Lookup char into string, return position */
int mk_string_char_search(const char *string, int c, int len);

/* Find char into string searching in reverse order, returns position */
int mk_string_char_search_r(const char *string, int c, int len);

/* Locate a substring, returns the position of the substring */
int mk_string_search(const char *haystack, const char *needle, int sensitive);

/* Locate a substring, compare the first n bytes of haystack */
int mk_string_search_n(const char *haystack, const char *needle, int sensitive, int len);

char *mk_string_remove_space(char *buf);
char *mk_string_casestr(char *heystack, char *needle);
char *mk_string_dup(const char *s);
struct mk_list *mk_string_split_line(const char *line);
void mk_string_split_free(struct mk_list *list);
int mk_string_trim(char **str);
char *mk_string_build(char **buffer, unsigned long *len,
                      const char *format, ...) PRINTF_WARNINGS(3,4);

#if defined (__GNUC__) || defined (_WIN32)
int mk_string_itop(uint64_t value, mk_ptr_t *p);
#endif

char *mk_string_copy_substr(const char *string, int pos_init, int pos_end);

char *mk_string_tolower(const char *in);

#if defined (__APPLE__) || defined (_WIN32)
void *memrchr(const void *s, int c, size_t n);
#endif

#ifdef _WIN32
char *strndup (const char *s, size_t n);
char *strcasestr(const char *phaystack, const char *pneedle);
#endif

#endif
