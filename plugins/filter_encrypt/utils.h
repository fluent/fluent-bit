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
#include <stdio.h>
#include <string.h>

#ifndef UTILS_H_
#define UTILS_H_

void print_bytes(unsigned char* buf, const size_t len);
void block_xor(unsigned char* dst, unsigned char* a, unsigned char* b);
void block_leftshift(unsigned char* dst, unsigned char* src);
char *concat(char *str1, const int str1_len, const char *str2, const int str2_len);
char* concaten(const char* str1, const int str1_len, const char* str2, const int str2_len);
char* substring(const char* input, size_t start, size_t length);
char* base64encode(const void* data, size_t input_length);
unsigned char* base64decode(const char* b64message, size_t b64message_len, size_t* output_length);
void populate_key_value_delimiters(char *value_delimiters);
void handleErrors(void);
#endif //UTILS_H_
