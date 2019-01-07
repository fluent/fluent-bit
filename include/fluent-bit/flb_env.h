/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#ifndef FLB_END_H
#define FLB_END_H

#define FLB_ENV_SIZE 64

struct flb_env {
    struct flb_hash *ht;
};

struct flb_env *flb_env_create();
void flb_env_destroy(struct flb_env *env);
int flb_env_set(struct flb_env *env, char *key, char *val);
char *flb_env_get(struct flb_env *env, char *key);
char *flb_env_var_translate(struct flb_env *env, char *value);

#endif
