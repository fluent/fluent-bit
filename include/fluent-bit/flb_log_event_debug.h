/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#ifndef FLB_LOG_EVENT_DEBUG_H
#define FLB_LOG_EVENT_DEBUG_H

#include <msgpack.h>
#include <ctype.h>

static inline void flb_hex_dump(uint8_t *buffer, size_t buffer_length, size_t line_length) {
    char  *printable_line;
    size_t buffer_index;
    size_t filler_index;

    if (40 < line_length)
    {
        line_length = 40;
    }

    printable_line = alloca(line_length + 1);

    if (NULL == printable_line)
    {
        printf("Alloca returned NULL\n");

        return;
    }

    memset(printable_line, '\0', line_length + 1);

    for (buffer_index = 0 ; buffer_index < buffer_length ; buffer_index++) {
        if (0 != buffer_index &&
            0 == (buffer_index % line_length)) {

            printf("%s\n", printable_line);

            memset(printable_line, '\0', line_length + 1);
        }

        if (0 != isprint(buffer[buffer_index])) {
            printable_line[(buffer_index % line_length)] = buffer[buffer_index];
        }
        else {
            printable_line[(buffer_index % line_length)] = '.';
        }

        printf("%02X ", buffer[buffer_index]);
    }

    if (0 != buffer_index &&
        0 != (buffer_index % line_length)) {

        for (filler_index = 0 ;
             filler_index < (line_length - (buffer_index % line_length)) ;
             filler_index++) {
            printf("   ");
        }

        printf("%s\n", printable_line);

        memset(printable_line, '.', line_length);
    }

}



static inline int flb_msgpack_dump(char *buffer, size_t length)
{
    msgpack_unpacked context;
    size_t           offset;
    int              result;

    offset = 0;

    printf("\n\nDUMPING %p (%zu)\n\n", buffer, length);
    flb_hex_dump((uint8_t *) buffer, length, 40);
    printf("\n\n");

    msgpack_unpacked_init(&context);

    while ((result = msgpack_unpack_next(&context, buffer, length, &offset) ==
           MSGPACK_UNPACK_SUCCESS)) {

        msgpack_object_print(stdout, context.data);
        printf("\n\n");
    }

    if (result != MSGPACK_UNPACK_SUCCESS) {
        printf("MSGPACK ERROR %d\n\n", result);
    }

    msgpack_unpacked_destroy(&context);

    return result;
}
