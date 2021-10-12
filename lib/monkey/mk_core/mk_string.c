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

#define _GNU_SOURCE
#include <string.h>

#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>

#include <mk_core/mk_core_info.h>
#include <mk_core/mk_macros.h>
#include <mk_core/mk_utils.h>
#include <mk_core/mk_memory.h>
#include <mk_core/mk_string.h>

#include <stdio.h>

/* OSX and Windows lacks of memrchr() */
#if !defined(MK_HAVE_MEMRCHR)
void *memrchr(const void *s, int c, size_t n)
{
    const unsigned char *cp;

    if (n != 0) {
        cp = (unsigned char *)s + n;
        do {
            if (*(--cp) == (unsigned char)c)
                return((void *)cp);
        } while (--n != 0);
    }
    return(NULL);
}
#endif

#ifndef MK_HAVE_MEMMEM
void *memmem(const void *haystack, size_t haystacklen,
             const void *needle, size_t needlelen)
{
    uint8_t *null_terminated_haystack_buffer;
    uint8_t *null_terminated_needle_buffer;
    uint8_t  free_haystack_buffer;
    uint8_t  free_needle_buffer;
    void    *result;

    result = NULL;

    free_haystack_buffer = 0;
    free_needle_buffer = 0;

    if(1024 > haystacklen){
        null_terminated_haystack_buffer = (uint8_t *)_alloca(haystacklen + 1);
    }
    else
    {
        null_terminated_haystack_buffer = (uint8_t*)malloc(haystacklen + 1);
        free_haystack_buffer = 1;
    }

    if(NULL != null_terminated_haystack_buffer){
        if(1024 > needlelen){
            null_terminated_needle_buffer = (uint8_t*)_alloca(needlelen + 1);
        }
        else
        {
            null_terminated_needle_buffer = (uint8_t*)malloc(needlelen + 1);
            free_needle_buffer = 1;
        }

        if(NULL != null_terminated_needle_buffer){
            memset(null_terminated_haystack_buffer, 0, haystacklen + 1);

            memcpy(null_terminated_haystack_buffer, haystack, haystacklen);

            memset(null_terminated_needle_buffer, 0, needlelen + 1);

            memcpy(null_terminated_needle_buffer, needle, needlelen);

            result = strstr(null_terminated_haystack_buffer, 
                            null_terminated_needle_buffer);

            if(free_needle_buffer){
                free(null_terminated_needle_buffer);
            }
        }

        if(free_haystack_buffer){
            free(null_terminated_haystack_buffer);
        }
    }

    return result;
}
#endif

/* Windows lack of strndup() & strcasestr() */
#ifdef _WIN32
char *strndup (const char *s, size_t n)
{
    char *result;
    size_t len = strlen (s);

    if (n < len) {
        len = n;
    }

    result = (char *) mk_mem_alloc(len + 1);
    if (!result) {
        return 0;
    }

    result[len] = '\0';
    return (char *) memcpy (result, s, len);
}

char *strcasestr(const char *phaystack, const char *pneedle)
{
	register const unsigned char *haystack, *needle;
	register unsigned bl, bu, cl, cu;

	haystack = (const unsigned char *) phaystack;
	needle = (const unsigned char *) pneedle;

	bl = tolower(*needle);
	if (bl != '\0')
	{
		// Scan haystack until the first character of needle is found:
		bu = toupper(bl);
		haystack--;				/* possible ANSI violation */
		do
		{
			cl = *++haystack;
			if (cl == '\0')
				goto ret0;
		}
		while ((cl != bl) && (cl != bu));

		cl = tolower(*++needle);
		if (cl == '\0') {
			goto foundneedle;
        }

		cu = toupper(cl);
		++needle;
		goto jin;

		for (;;)
		{
			register unsigned a;
			register const unsigned char *rhaystack, *rneedle;
			do
			{
				a = *++haystack;
				if (a == '\0')
					goto ret0;
				if ((a == bl) || (a == bu))
					break;
				a = *++haystack;
				if (a == '\0')
					goto ret0;
shloop:
				;
			}
			while ((a != bl) && (a != bu));

jin:
			a = *++haystack;
			if (a == '\0') {
				goto ret0;
            }

			if ((a != cl) && (a != cu)) {
				goto shloop;
            }

			rhaystack = haystack-- + 1;
			rneedle = needle;
			a = tolower(*rneedle);

			if (tolower(*rhaystack) == (int) a)
			do
			{
				if (a == '\0')
					goto foundneedle;
				++rhaystack;
				a = tolower(*++needle);
				if (tolower(*rhaystack) != (int) a)
					break;
				if (a == '\0')
					goto foundneedle;
				++rhaystack;
				a = tolower(*++needle);
			}
			while (tolower(*rhaystack) == (int) a);

			needle = rneedle;		/* took the register-poor approach */

			if (a == '\0')
				break;
		} // for(;;)
	} // if (bl != '\0')
foundneedle:
	return (char*) haystack;
ret0:
	return 0;
}
#endif

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
    p = mk_mem_alloc(len + 1);
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

    list = mk_mem_alloc(sizeof(struct mk_list));
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
        new = mk_mem_alloc(sizeof(struct mk_string_line));
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
    mk_bug(*buffer);
    *buffer = (char *) mk_mem_alloc(_mem_alloc);

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
        ptr = mk_mem_realloc(*buffer, length + 1);
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

uint32_t digits10(uint64_t v) {
    if (v < 10) return 1;
    if (v < 100) return 2;
    if (v < 1000) return 3;
    if (v < 1000000000000UL) {
        if (v < 100000000UL) {
            if (v < 1000000) {
                if (v < 10000) return 4;
                return 5 + (v >= 100000);
            }
            return 7 + (v >= 10000000UL);
        }
        if (v < 10000000000UL) {
            return 9 + (v >= 1000000000UL);
        }
        return 11 + (v >= 100000000000UL);
    }
    return 12 + digits10(v / 1000000000000UL);
}

#if defined(__GNUC__) || defined(_WIN32)
int mk_string_itop(uint64_t value, mk_ptr_t *p)
{
    static const char digits[201] =
        "0001020304050607080910111213141516171819"
        "2021222324252627282930313233343536373839"
        "4041424344454647484950515253545556575859"
        "6061626364656667686970717273747576777879"
        "8081828384858687888990919293949596979899";

    uint32_t const length = digits10(value);
    uint32_t next = length - 1;
    char *dst = p->data;

    while (value >= 100) {
        int const i = (value % 100) * 2;
        value /= 100;
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
        next -= 2;
    }

    /* Handle last 1-2 digits */
    if (value < 10) {
        dst[next] = '0' + (uint32_t) value;
    }
    else {
        int i = (uint32_t) value * 2;
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
    }

    dst = p->data + length;
    *dst++ = '\r';
    *dst++ = '\n';
    *dst++ = '\0';

    p->len = (dst - p->data - 1);
    return p->len;
}
#endif

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

    buffer = mk_mem_alloc(size);

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
