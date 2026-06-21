/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2026 The CFL Authors
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

#ifndef CFL_CONTAINER_H
#define CFL_CONTAINER_H

#include <cfl/cfl_array.h>
#include <cfl/cfl_kvlist.h>
#include <cfl/cfl_variant.h>

int cfl_container_array_contains_array(struct cfl_array *array,
                                       struct cfl_array *target);
int cfl_container_array_contains_kvlist(struct cfl_array *array,
                                        struct cfl_kvlist *target);
int cfl_container_array_contains_variant(struct cfl_array *array,
                                         struct cfl_variant *target);

int cfl_container_kvlist_contains_array(struct cfl_kvlist *kvlist,
                                        struct cfl_array *target);
int cfl_container_kvlist_contains_kvlist(struct cfl_kvlist *kvlist,
                                         struct cfl_kvlist *target);
int cfl_container_kvlist_contains_variant(struct cfl_kvlist *kvlist,
                                          struct cfl_variant *target);

int cfl_container_variant_contains_array(struct cfl_variant *variant,
                                         struct cfl_array *target);
int cfl_container_variant_contains_kvlist(struct cfl_variant *variant,
                                          struct cfl_kvlist *target);
int cfl_container_variant_contains_variant(struct cfl_variant *variant,
                                           struct cfl_variant *target);

int cfl_container_claim_array(struct cfl_array *array,
                              struct cfl_variant *owner);
int cfl_container_claim_kvlist(struct cfl_kvlist *kvlist,
                               struct cfl_variant *owner);
int cfl_container_adopt_variant(struct cfl_variant *variant);
int cfl_container_move_variant_to_array(struct cfl_array *array,
                                        struct cfl_variant *variant);
int cfl_container_move_variant_to_kvlist(struct cfl_kvlist *kvlist,
                                         struct cfl_variant *variant);
void cfl_container_release_variant(struct cfl_variant *variant);

#endif
