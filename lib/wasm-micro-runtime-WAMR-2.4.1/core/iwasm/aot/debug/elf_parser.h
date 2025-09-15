/*
 * Copyright (C) 2021 Ant Group.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _ELF_PARSER_H_
#define _ELF_PARSER_H_
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool
is_ELF(void *buf);

bool
is_ELF64(void *buf);

bool
get_text_section(void *buf, uint64_t *offset, uint64_t *size);

#ifdef __cplusplus
}
#endif

#endif
