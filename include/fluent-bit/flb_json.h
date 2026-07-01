/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#ifndef FLB_JSON_H
#define FLB_JSON_H

#include <stddef.h>

struct flb_json_doc;
struct flb_json_val;
struct flb_json_mut_doc;
struct flb_json_mut_val;

struct flb_json_doc *flb_json_read(const char *input, size_t length);
void flb_json_doc_destroy(struct flb_json_doc *document);
struct flb_json_val *flb_json_doc_get_root(struct flb_json_doc *document);
char *flb_json_write(struct flb_json_doc *document, size_t *length);
char *flb_json_write_pretty(struct flb_json_doc *document, size_t *length);
char *flb_json_prettify(const char *input, size_t input_length, size_t *length);
struct flb_json_val *flb_json_obj_get(struct flb_json_val *value,
                                      const char *key);
size_t flb_json_arr_size(struct flb_json_val *value);
struct flb_json_val *flb_json_arr_get(struct flb_json_val *value, size_t index);

struct flb_json_mut_doc *flb_json_mut_doc_create(void);
void flb_json_mut_doc_destroy(struct flb_json_mut_doc *document);
void flb_json_mut_doc_set_root(struct flb_json_mut_doc *document,
                               struct flb_json_mut_val *root);
char *flb_json_mut_write(struct flb_json_mut_doc *document, size_t *length);
char *flb_json_mut_write_pretty(struct flb_json_mut_doc *document, size_t *length);

struct flb_json_mut_val *flb_json_mut_obj(struct flb_json_mut_doc *document);
struct flb_json_mut_val *flb_json_mut_arr(struct flb_json_mut_doc *document);
struct flb_json_mut_val *flb_json_mut_strncpy(struct flb_json_mut_doc *document,
                                              const char *value,
                                              size_t length);
struct flb_json_mut_val *flb_json_val_mut_copy(struct flb_json_mut_doc *target,
                                               struct flb_json_val *source);

int flb_json_mut_arr_add_real(struct flb_json_mut_doc *document,
                              struct flb_json_mut_val *array,
                              double value);
int flb_json_mut_arr_add_strncpy(struct flb_json_mut_doc *document,
                                 struct flb_json_mut_val *array,
                                 const char *value,
                                 size_t length);
int flb_json_mut_arr_add_val(struct flb_json_mut_val *array,
                             struct flb_json_mut_val *value);
size_t flb_json_mut_arr_size(struct flb_json_mut_val *array);

int flb_json_mut_obj_add_bool(struct flb_json_mut_doc *document,
                              struct flb_json_mut_val *object,
                              const char *key,
                              int value);
int flb_json_mut_obj_add_int(struct flb_json_mut_doc *document,
                             struct flb_json_mut_val *object,
                             const char *key,
                             long long value);
int flb_json_mut_obj_add_real(struct flb_json_mut_doc *document,
                              struct flb_json_mut_val *object,
                              const char *key,
                              double value);
int flb_json_mut_obj_add_str(struct flb_json_mut_doc *document,
                             struct flb_json_mut_val *object,
                             const char *key,
                             const char *value);
int flb_json_mut_obj_add_strcpy(struct flb_json_mut_doc *document,
                                struct flb_json_mut_val *object,
                                const char *key,
                                const char *value);
int flb_json_mut_obj_add_strn(struct flb_json_mut_doc *document,
                              struct flb_json_mut_val *object,
                              const char *key,
                              const char *value,
                              size_t length);
int flb_json_mut_obj_add_strncpy(struct flb_json_mut_doc *document,
                                 struct flb_json_mut_val *object,
                                 const char *key,
                                 const char *value,
                                 size_t length);
int flb_json_mut_obj_add_uint(struct flb_json_mut_doc *document,
                              struct flb_json_mut_val *object,
                              const char *key,
                              unsigned long long value);
int flb_json_mut_obj_add_val(struct flb_json_mut_doc *document,
                             struct flb_json_mut_val *object,
                             const char *key,
                             struct flb_json_mut_val *value);

#endif
