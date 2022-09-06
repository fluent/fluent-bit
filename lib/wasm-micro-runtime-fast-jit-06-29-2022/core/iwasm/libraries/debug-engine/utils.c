/*
 * Copyright (C) 2021 Ant Group.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "utils.h"

static const char hexchars[] = "0123456789abcdef";

int32
hex(char ch)
{
    if ((ch >= 'a') && (ch <= 'f'))
        return (ch - 'a' + 10);
    if ((ch >= '0') && (ch <= '9'))
        return (ch - '0');
    if ((ch >= 'A') && (ch <= 'F'))
        return (ch - 'A' + 10);
    return (-1);
}

char *
mem2hex(char *mem, char *buf, int32 count)
{
    uint8 ch;

    for (int i = 0; i < count; i++) {
        ch = *(mem++);
        *buf++ = hexchars[ch >> 4];
        *buf++ = hexchars[ch % 16];
    }
    *buf = 0;
    return (buf);
}

char *
hex2mem(char *buf, char *mem, int32 count)
{
    uint8 ch;

    for (int i = 0; i < count; i++) {
        ch = hex(*buf++) << 4;
        ch = ch + hex(*buf++);
        *(mem++) = ch;
    }
    return (mem);
}
