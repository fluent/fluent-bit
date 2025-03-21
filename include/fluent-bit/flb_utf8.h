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

#ifndef FLB_UTF8_H
#define FLB_UTF8_H

#define FLB_UTF8_ACCEPT   0
#define FLB_UTF8_REJECT   1
#define FLB_UTF8_CONTINUE 2

#include <fluent-bit/flb_info.h>
#include <inttypes.h>

/* returns length of next utf-8 sequence */
int flb_utf8_len(const char *s);
uint32_t flb_utf8_decode(uint32_t *state, uint32_t *codep, uint8_t byte);
void flb_utf8_print(char *input);

#endif
