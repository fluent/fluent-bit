/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2022 The CFL Authors
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

#include <cfl/cfl.h>

#include <limits.h>
#include <stdint.h>

/* Lookup char into string, return position
 * Based on monkey/monkey's mk_string_char_search.
 */
static int cfl_string_char_search(const char *string, int c, int len)
{
    char *p;
    size_t string_len;

    if (string == NULL) {
        return -1;
    }

    if (len < 0) {
        string_len = strlen(string);
        if (string_len > INT_MAX) {
            return -1;
        }

        len = (int) string_len;
    }

    p = memchr(string, c, len);
    if (p) {
        return (p - string);
    }

    return -1;
}

/* Return a buffer with a new string from string.
 * Based on monkey/monkey's mk_string_copy_substr.
 */
static char *cfl_string_copy_substr(const char *string, int pos_init, int pos_end)
{
    size_t size;
    size_t bytes;
    char *buffer = 0;

    if (string == NULL || pos_init < 0 || pos_end < 0 || pos_init > pos_end) {
        return NULL;
    }

    bytes = (size_t) (pos_end - pos_init);
    if (bytes > SIZE_MAX - 1) {
        return NULL;
    }

    size = bytes + 1;
    if (size <= 2) {
        size = 4;
    }

    buffer = calloc(1, size);

    if (!buffer) {
        return NULL;
    }

    memcpy(buffer, string + pos_init, bytes);
    buffer[bytes] = '\0';

    return (char *) buffer;
}

/*
 * quoted_string_len returns the length of a quoted string, not including the quotes.
 */
static int quoted_string_len(const char *str)
{
    int len = 0;
    char quote;

    if (str == NULL) {
        return -1;
    }

    quote = *str++; /* Consume the quote character. */

    while (quote != 0) {
        char c = *str++;
        switch (c) {
            case '\0':
                /* Error: string ends before end-quote was seen. */
                return -1;
            case '\\':
                /* Skip escaped quote or \\. */
                if (*str == quote || *str == '\\') {
                    str++;
                }
                break;
            case '\'':
            case '"':
                /* End-quote seen: stop iterating. */
                if (c == quote) {
                    quote = 0;
                }
                break;
            default:
                break;
        }
        if (len == INT_MAX) {
            return -1;
        }
        len++;
    }

    /* Go back one character to ignore end-quote */
    len--;

    return len;
}

/*
 * next_token returns the next token in the string 'str' delimited by 'separator'.
 * 'out' is set to the beginning of the token.
 * 'out_len' is set to the length of the token.
 * 'parse_quotes' is set to CFL_TRUE when quotes shall be considered when tokenizing the 'str'.
 * The function returns offset to next token in the string.
 */
static int next_token(const char *str, int separator, char **out, int *out_len, int parse_quotes) {
    const char *token_in = str;
    char *token_out;
    size_t token_len;
    int next_separator = 0;
    int quote = 0; /* Parser state: 0 not inside quoted string, or '"' or '\'' when inside quoted string. */
    int len = 0;
    int i;

    if (str == NULL || out == NULL || out_len == NULL) {
        return -1;
    }

    /* Skip leading separators. */
    while (*token_in == separator) {
        token_in++;
    }

    /* Should quotes be parsed? Or is token quoted? If not, copy until separator or the end of string. */
    if (parse_quotes == CFL_FALSE || (*token_in != '"' && *token_in != '\'')) {
        token_len = strlen(token_in);
        if (token_len > INT_MAX) {
            return -1;
        }

        len = (int) token_len;
        next_separator = cfl_string_char_search(token_in, separator, len);
        if (next_separator > 0) {
            len = next_separator;
        }
        *out_len = len;
        *out = cfl_string_copy_substr(token_in, 0, len);
        if (*out == NULL) {
            return -1;
        }

        return (int)(token_in - str) + len;
    }

    /* Token is quoted. */

    len = quoted_string_len(token_in);
    if (len < 0) {
        return -1;
    }

    /* Consume the quote character. */
    quote = *token_in++;

    token_out = calloc(1, len + 1);
    if (!token_out) {
        return -1;
    }

    /* Copy the token */
    for (i = 0; i < len; i++) {
        /* Handle escapes when inside quoted token:
         *   \" -> "
         *   \' -> '
         *   \\ -> \
         */
        if (*token_in == '\\' && (token_in[1] == quote || token_in[1] == '\\')) {
            token_in++;
        }
        token_out[i] = *token_in++;
    }
    token_out[i] = '\0';

    *out = token_out;
    *out_len = len;

    return (int)(token_in - str);
}


static struct cfl_list *split(const char *line, int separator, int max_split, int quoted)
{
    int i = 0;
    int count = 0;
    int val_len;
    int len;
    int end;
    size_t line_len;
    char *val;
    struct cfl_list *list;
    struct cfl_split_entry *new;

    if (!line) {
        return NULL;
    }

    list = calloc(1, sizeof(struct cfl_list));
    if (!list) {
        cfl_errno();
        return NULL;
    }
    cfl_list_init(list);

    line_len = strlen(line);
    if (line_len > INT_MAX) {
        free(list);
        return NULL;
    }

    len = (int) line_len;
    while (i < len) {
        end = next_token(line + i, separator, &val, &val_len, quoted);
        if (end == -1) {
            cfl_report_runtime_error();
            cfl_utils_split_free(list);
            return NULL;
        }

        /* Update last position */
        i += end;

        /* Create new entry */
        new = calloc(1, sizeof(struct cfl_split_entry));
        if (!new) {
            cfl_errno();
            free(val);
            cfl_utils_split_free(list);
            return NULL;
        }
        new->value = val;
        new->len = val_len;
        new->last_pos = i;
        cfl_list_add(&new->_head, list);
        count++;

        /* Update index for next loop */
        i++;

        /*
         * If the counter exceeded the maximum specified and there
         * are still remaining bytes, append those bytes in a new
         * and last entry.
         */
        if (count >= max_split && max_split > 0 && i < len) {
            new = calloc(1, sizeof(struct cfl_split_entry));
            if (!new) {
                cfl_errno();
                cfl_utils_split_free(list);
                return NULL;
            }
            new->value = cfl_string_copy_substr(line, i, len);
            if (new->value == NULL) {
                cfl_errno();
                free(new);
                cfl_utils_split_free(list);
                return NULL;
            }
            new->len   = len - i;
            cfl_list_add(&new->_head, list);
            break;
        }
    }

    return list;
}

struct cfl_list *cfl_utils_split_quoted(const char *line, int separator, int max_split)
{
    return split(line, separator, max_split, CFL_TRUE);
}

struct cfl_list *cfl_utils_split(const char *line, int separator, int max_split)
{
    return split(line, separator, max_split, CFL_FALSE);
}


void cfl_utils_split_free_entry(struct cfl_split_entry *entry)
{
    if (entry == NULL) {
        return;
    }

    cfl_list_del(&entry->_head);
    free(entry->value);
    free(entry);
}

void cfl_utils_split_free(struct cfl_list *list)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct cfl_split_entry *entry;

    if (list == NULL) {
        return;
    }

    cfl_list_foreach_safe(head, tmp, list) {
        entry = cfl_list_entry(head, struct cfl_split_entry, _head);
        cfl_utils_split_free_entry(entry);
    }

    free(list);
}
