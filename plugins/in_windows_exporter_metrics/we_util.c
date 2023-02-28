/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_sds.h>

#include "we.h"
#include "we_util.h"

int we_get_windows_version(double *version_number)
{
    LSTATUS result;
    DWORD   data_size;
    HKEY    key_handle;
    char    version_text[8];

    data_size = sizeof(version_text);

    result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                           WE_VERSION_REGISTRY_PATH,
                           0,
                           KEY_READ,
                           &key_handle);

    if (result != ERROR_SUCCESS) {
        return FLB_FALSE;
    }

    result = RegQueryValueExA(key_handle,
                              WE_VERSION_KEY_NAME,
                              NULL,
                              0,
                              version_text,
                              &data_size);

    RegCloseKey(key_handle);

    if (result != ERROR_SUCCESS)
    {
        return FLB_FALSE;
    }

    *version_number = strtod(version_text, NULL);

    return FLB_TRUE;
}

void we_hexdump(uint8_t *buffer, size_t buffer_length, size_t line_length) {
    char  *printable_line;
    size_t buffer_index;
    size_t filler_index;

    if (40 < line_length)
    {
        line_length = 40;
    }

    printable_line = malloc(line_length + 1);

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

    free(printable_line);
}

char* we_convert_wstr(wchar_t *wstr, UINT codePage)
{
    int size = 0;
    char *buf = NULL;

    size = WideCharToMultiByte(codePage, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (size == 0) {
        return NULL;
    }

    buf = flb_calloc(1, size);
    if (buf == NULL) {
        flb_errno();
        return NULL;
    }
    size = WideCharToMultiByte(codePage, 0, wstr, -1, buf, size, NULL, NULL);
    if (size == 0) {
        flb_free(buf);
        return NULL;
    }

    return buf;
}

wchar_t* we_convert_str(char *str)
{
    int size = 0;
    wchar_t *buf = NULL;

    size = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (size == 0) {
        return NULL;
    }

    buf = flb_calloc(1, sizeof(PWSTR) * size);
    if (buf == NULL) {
        flb_errno();
        return NULL;
    }
    size = MultiByteToWideChar(CP_UTF8, 0, str, -1, buf, size);
    if (size == 0) {
        flb_free(buf);
        return NULL;
    }

    return buf;
}
