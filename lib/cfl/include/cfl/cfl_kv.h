/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2022 The CFL Authors
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

#ifndef CFL_KV_H
#define CFL_KV_H

#include <cfl/cfl_info.h>
#include <cfl/cfl_sds.h>
#include <cfl/cfl_list.h>

struct cfl_kv {
  cfl_sds_t       key;
  cfl_sds_t       val;
  struct cfl_list _head;
};

void cfl_kv_init(struct cfl_list *list);
struct cfl_kv *cfl_kv_item_create_len(struct cfl_list *list,
                                      char *k_buf, size_t k_len,
                                      char *v_buf, size_t v_len);
struct cfl_kv *cfl_kv_item_create(struct cfl_list *list,
                                  char *k_buf, char *v_buf);
void cfl_kv_item_destroy(struct cfl_kv *kv);
void cfl_kv_release(struct cfl_list *list);
const char *cfl_kv_get_key_value(const char *key, struct cfl_list *list);

#endif
