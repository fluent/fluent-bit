/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_utf8.h>

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

static const char trailing_bytes_for_utf8[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 3,3,3,3,3,3,3,3,4,4,4,4,5,5,5,5
};

/* returns length of next utf-8 sequence */
int flb_utf8_len(const char *s)
{
    return trailing_bytes_for_utf8[(unsigned int)(unsigned char)s[0]] + 1;
}

uint32_t flb_utf8_decode(uint32_t *state, uint32_t *codep, uint8_t byte)
{
    /* Start of a new character */
    if (*state == 0) {
        if (byte <= 0x7F) {
            /* ASCII */
            *codep = byte;
            return FLB_UTF8_ACCEPT;
        }
        else if ((byte & 0xE0) == 0xC0) {
            /* start of a 2-byte sequence */
            *codep = byte & 0x1F;
            *state = 1;
        }
        else if ((byte & 0xF0) == 0xE0) {
            /* start of a 3-byte sequence */
            *codep = byte & 0x0F;
            *state = 2;
        }
        else if ((byte & 0xF8) == 0xF0) {
            /* start of a 4-byte sequence */
            *codep = byte & 0x07;
            *state = 3;
        }
        else {
            /* invalid first byte */
            *state = FLB_UTF8_REJECT;
            return FLB_UTF8_REJECT;
        }
    }
    else {
        /* continuation byte */
        if ((byte & 0xC0) == 0x80) {
            *codep = (*codep << 6) | (byte & 0x3F);

            /* reduce the expected continuation bytes */
            (*state)--;
        }
        else {
            /* invalid continuation byte */
            *state = FLB_UTF8_REJECT;
            return FLB_UTF8_REJECT;
        }
    }

    if (*state == 0) {
        /* sequence complete */
        if (*codep >= 0xD800 && *codep <= 0xDFFF) {
            /* invalid surrogate pair */
            *state = FLB_UTF8_REJECT;
            return FLB_UTF8_REJECT;
        }
        else if (*codep > 0x10FFFF) {
            /* codepoint is out of range */
            *state = FLB_UTF8_REJECT;
            return FLB_UTF8_REJECT;
        }
        return FLB_UTF8_ACCEPT;
    }

    /* we are still processing the current sequence */
    return FLB_UTF8_CONTINUE;
}

void flb_utf8_print(char *input)
{
    int i;
    int ret;
    int len;
    uint32_t state = 0;
    uint32_t codepoint = 0;

    len = strlen(input);
    for (i = 0; i < len; i++) {
        ret = flb_utf8_decode(&state, &codepoint, (uint8_t) input[i]);
        if (ret == FLB_UTF8_ACCEPT) {
            printf("Valid Codepoint: U+%04X\n", codepoint);
        }
        else if (ret == FLB_UTF8_REJECT) {
            printf("Invalid UTF-8 sequence detected.\n");
            break;
        }
    }
}
