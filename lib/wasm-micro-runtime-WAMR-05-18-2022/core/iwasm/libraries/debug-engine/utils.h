/*
 * Copyright (C) 2021 Ant Group.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef UTILS_H
#define UTILS_H

#include "bh_platform.h"

int32
hex(char ch);

char *
mem2hex(char *mem, char *buf, int32 count);

char *
hex2mem(char *buf, char *mem, int32 count);

int32
unescape(char *msg, int32 len);

#endif /* UTILS_H */
