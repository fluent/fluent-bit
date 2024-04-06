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

#ifndef CFL_OBJECT_H
#define CFL_OBJECT_H

enum {
    CFL_OBJECT_NONE = 0,
    CFL_OBJECT_KVLIST = 1,
    CFL_OBJECT_VARIANT,
    CFL_OBJECT_ARRAY
};

struct cfl_object {
    int type;
    struct cfl_variant *variant;
    struct cfl_list _head;
};

struct cfl_object *cfl_object_create();
void cfl_object_destroy(struct cfl_object *obj);
int cfl_object_set(struct cfl_object *o, int type, void *ptr);
int cfl_object_print(FILE *stream, struct cfl_object *o);

#endif
