/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

static int octal_digit(char c)
{
    return (c >= '0' && c <= '7');
}

static int hex_digit(char c)
{
    return ((c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'F') ||
            (c >= 'a' && c <= 'f'));
}

static int u8_wc_toutf8(char *dest, uint32_t ch)
{
    if (ch < 0x80) {
        dest[0] = (char)ch;
        return 1;
    }
    if (ch < 0x800) {
        dest[0] = (ch>>6) | 0xC0;
        dest[1] = (ch & 0x3F) | 0x80;
        return 2;
    }
    if (ch < 0x10000) {
        dest[0] = (ch>>12) | 0xE0;
        dest[1] = ((ch>>6) & 0x3F) | 0x80;
        dest[2] = (ch & 0x3F) | 0x80;
        return 3;
    }
    if (ch < 0x110000) {
        dest[0] = (ch>>18) | 0xF0;
        dest[1] = ((ch>>12) & 0x3F) | 0x80;
        dest[2] = ((ch>>6) & 0x3F) | 0x80;
        dest[3] = (ch & 0x3F) | 0x80;
        return 4;
    }
    return 0;
}

/* assumes that src points to the character after a backslash
   returns number of input characters processed */
static int u8_read_escape_sequence(const char *str, uint32_t *dest)
{
    uint32_t ch;
    char digs[9]="\0\0\0\0\0\0\0\0";
    int dno=0, i=1;

    ch = (uint32_t)str[0];    /* take literal character */

    if (str[0] == 'n')
        ch = L'\n';
    else if (str[0] == 't')
        ch = L'\t';
    else if (str[0] == 'r')
        ch = L'\r';
    else if (str[0] == 'b')
        ch = L'\b';
    else if (str[0] == 'f')
        ch = L'\f';
    else if (str[0] == 'v')
        ch = L'\v';
    else if (str[0] == 'a')
        ch = L'\a';
    else if (octal_digit(str[0])) {
        i = 0;
        do {
            digs[dno++] = str[i++];
        } while (octal_digit(str[i]) && dno < 3);
        ch = strtol(digs, NULL, 8);
    }
    else if (str[0] == 'x') {
        while (hex_digit(str[i]) && dno < 2) {
            digs[dno++] = str[i++];
        }
        if (dno > 0)
            ch = strtol(digs, NULL, 16);
    }
    else if (str[0] == 'u') {
        while (hex_digit(str[i]) && dno < 4) {
            digs[dno++] = str[i++];
        }
        if (dno > 0)
            ch = strtol(digs, NULL, 16);
    }
    else if (str[0] == 'U') {
        while (hex_digit(str[i]) && dno < 8) {
            digs[dno++] = str[i++];
        }
        if (dno > 0)
            ch = strtol(digs, NULL, 16);
    }
    *dest = ch;

    return i;
}

int flb_unescape_string_utf8(const char *in_buf, int sz, char *out_buf)
{
    uint32_t ch;
    char temp[4];
    const char *end;
    const char *next;

    int count_out = 0;
    int count_in = 0;
    int esc_in = 0;
    int esc_out = 0;

    end = in_buf + sz;
    while (in_buf < end && *in_buf && count_in < sz) {
        next = in_buf + 1;
        if (next < end && *in_buf == '\\') {
            esc_in = 2;
            switch (*next) {
            case '"':
                ch = '"';
                break;
            case '\'':
                ch = '\'';
                break;
            case '\\':
                ch = '\\';
                break;
            case '/':
                ch = '/';
                break;
            case 'n':
                ch = '\n';
                break;
            case 'b':
                ch = '\b';
                break;
            case 't':
                ch = '\t';
                break;
            case 'f':
                ch = '\f';
                break;
            case 'r':
                ch = '\r';
                break;
            default:
                esc_in = u8_read_escape_sequence((in_buf + 1), &ch) + 1;
            }
        }
        else {
            ch = (uint32_t) *in_buf;
            esc_in = 1;
        }

        in_buf += esc_in;
        count_in += esc_in;

        esc_out = u8_wc_toutf8(temp, ch);
        if (esc_out > sz-count_out) {
            flb_error("Crossing over string boundary");
            break;
        }

        if (esc_out == 0) {
            out_buf[count_out] = ch;
            esc_out = 1;
        }
        else if (esc_out == 1) {
            out_buf[count_out] = (char) temp[0];
        }
        else {
            memcpy(&out_buf[count_out], temp, esc_out);
        }
        count_out += esc_out;
    }
    if (count_in < sz) {
        flb_error("Not at boundary but still NULL terminating : %d - '%s'", sz, in_buf);
    }
    out_buf[count_out] = '\0';
    return count_out;
}

int flb_unescape_string(const char *buf, int buf_len, char **unesc_buf)
{
    int i = 0;
    int j = 0;
    char *p;
    char n;

    p = *unesc_buf;
    while (i < buf_len) {
        if (buf[i] == '\\') {
            if (i + 1 < buf_len) {
                n = buf[i + 1];
                if (n == 'n') {
                    p[j++] = '\n';
                    i++;
                }
                else if (n == 'a') {
                    p[j++] = '\a';
                    i++;
                }
                else if (n == 'b') {
                    p[j++] = '\b';
                    i++;
                }
                else if (n == 't') {
                    p[j++] = '\t';
                    i++;
                }
                else if (n == 'v') {
                    p[j++] = '\v';
                    i++;
                }
                else if (n == 'f') {
                    p[j++] = '\f';
                    i++;
                }
                else if (n == 'r') {
                    p[j++] = '\r';
                    i++;
                }
                else if (n == '\\') {
                    p[j++] = '\\';
                    i++;
                }
                i++;
                continue;
            }
            else {
                i++;
            }
        }
        p[j++] = buf[i++];
    }
    p[j] = '\0';
    return j;
}


/* mysql unquote */
int flb_mysql_unquote_string(char *buf, int buf_len, char **unesc_buf)
{
    int i = 0;
    int j = 0;
    char *p;
    char n;

    p = *unesc_buf;
    while (i < buf_len) {
        if ((n = buf[i++]) != '\\') {
            p[j++] = n;
        } else if(i >= buf_len) {
            p[j++] = n;
        } else {
            n = buf[i++];
            switch(n) {
            case 'n':
                p[j++] = '\n';
                break;
            case 'r':
                p[j++] = '\r';
                break;
            case 't':
                p[j++] = '\t';
                break;
            case '\\':
                p[j++] = '\\';
                break;
            case '\'':
                p[j++] = '\'';
                break;
            case '\"':
                p[j++] = '\"';
                break;
            case '0':
                p[j++] = 0;
                break;
            case 'Z':
                p[j++] = 0x1a;
                break;
            default:
                p[j++] = '\\';
                p[j++] = n;
                break;
            }
        }
    }
    p[j] = '\0';
    return j;
}
