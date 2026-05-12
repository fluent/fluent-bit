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

#include <cfl/cfl.h>

#include <cfl/cfl_container.h>

#define CFL_CONTAINER_MAX_DEPTH 512

static int variant_contains_array(struct cfl_variant *variant,
                                  struct cfl_array *target,
                                  size_t depth);
static int variant_contains_kvlist(struct cfl_variant *variant,
                                   struct cfl_kvlist *target,
                                   size_t depth);
static int variant_contains_variant(struct cfl_variant *variant,
                                    struct cfl_variant *target,
                                    size_t depth);

static int depth_exceeded(size_t depth)
{
    if (depth > CFL_CONTAINER_MAX_DEPTH) {
        return CFL_TRUE;
    }

    return CFL_FALSE;
}

static int array_contains_array(struct cfl_array *array,
                                struct cfl_array *target,
                                size_t depth)
{
    size_t i;

    if (array == NULL || target == NULL) {
        return CFL_FALSE;
    }

    if (depth_exceeded(depth)) {
        return CFL_TRUE;
    }

    if (array == target) {
        return CFL_TRUE;
    }

    for (i = 0; i < array->entry_count; i++) {
        if (variant_contains_array(array->entries[i], target, depth + 1)) {
            return CFL_TRUE;
        }
    }

    return CFL_FALSE;
}

static int array_contains_kvlist(struct cfl_array *array,
                                 struct cfl_kvlist *target,
                                 size_t depth)
{
    size_t i;

    if (array == NULL || target == NULL) {
        return CFL_FALSE;
    }

    if (depth_exceeded(depth)) {
        return CFL_TRUE;
    }

    for (i = 0; i < array->entry_count; i++) {
        if (variant_contains_kvlist(array->entries[i], target, depth + 1)) {
            return CFL_TRUE;
        }
    }

    return CFL_FALSE;
}

static int array_contains_variant(struct cfl_array *array,
                                  struct cfl_variant *target,
                                  size_t depth)
{
    size_t i;

    if (array == NULL || target == NULL) {
        return CFL_FALSE;
    }

    if (depth_exceeded(depth)) {
        return CFL_TRUE;
    }

    for (i = 0; i < array->entry_count; i++) {
        if (variant_contains_variant(array->entries[i], target, depth + 1)) {
            return CFL_TRUE;
        }
    }

    return CFL_FALSE;
}

static int kvlist_contains_array(struct cfl_kvlist *kvlist,
                                 struct cfl_array *target,
                                 size_t depth)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;

    if (kvlist == NULL || target == NULL) {
        return CFL_FALSE;
    }

    if (depth_exceeded(depth)) {
        return CFL_TRUE;
    }

    cfl_list_foreach(head, &kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);

        if (pair != NULL && variant_contains_array(pair->val, target, depth + 1)) {
            return CFL_TRUE;
        }
    }

    return CFL_FALSE;
}

static int kvlist_contains_kvlist(struct cfl_kvlist *kvlist,
                                  struct cfl_kvlist *target,
                                  size_t depth)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;

    if (kvlist == NULL || target == NULL) {
        return CFL_FALSE;
    }

    if (depth_exceeded(depth)) {
        return CFL_TRUE;
    }

    if (kvlist == target) {
        return CFL_TRUE;
    }

    cfl_list_foreach(head, &kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);

        if (pair != NULL && variant_contains_kvlist(pair->val, target, depth + 1)) {
            return CFL_TRUE;
        }
    }

    return CFL_FALSE;
}

static int kvlist_contains_variant(struct cfl_kvlist *kvlist,
                                   struct cfl_variant *target,
                                   size_t depth)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;

    if (kvlist == NULL || target == NULL) {
        return CFL_FALSE;
    }

    if (depth_exceeded(depth)) {
        return CFL_TRUE;
    }

    cfl_list_foreach(head, &kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);

        if (pair != NULL && variant_contains_variant(pair->val, target, depth + 1)) {
            return CFL_TRUE;
        }
    }

    return CFL_FALSE;
}

static int variant_contains_array(struct cfl_variant *variant,
                                  struct cfl_array *target,
                                  size_t depth)
{
    if (variant == NULL || target == NULL) {
        return CFL_FALSE;
    }

    if (depth_exceeded(depth)) {
        return CFL_TRUE;
    }

    if (variant->type == CFL_VARIANT_ARRAY) {
        return array_contains_array(variant->data.as_array, target, depth + 1);
    }

    if (variant->type == CFL_VARIANT_KVLIST) {
        return kvlist_contains_array(variant->data.as_kvlist, target, depth + 1);
    }

    return CFL_FALSE;
}

static int variant_contains_kvlist(struct cfl_variant *variant,
                                   struct cfl_kvlist *target,
                                   size_t depth)
{
    if (variant == NULL || target == NULL) {
        return CFL_FALSE;
    }

    if (depth_exceeded(depth)) {
        return CFL_TRUE;
    }

    if (variant->type == CFL_VARIANT_ARRAY) {
        return array_contains_kvlist(variant->data.as_array, target, depth + 1);
    }

    if (variant->type == CFL_VARIANT_KVLIST) {
        return kvlist_contains_kvlist(variant->data.as_kvlist, target, depth + 1);
    }

    return CFL_FALSE;
}

static int variant_contains_variant(struct cfl_variant *variant,
                                    struct cfl_variant *target,
                                    size_t depth)
{
    if (variant == NULL || target == NULL) {
        return CFL_FALSE;
    }

    if (depth_exceeded(depth)) {
        return CFL_TRUE;
    }

    if (variant == target) {
        return CFL_TRUE;
    }

    if (variant->type == CFL_VARIANT_ARRAY) {
        return array_contains_variant(variant->data.as_array, target, depth + 1);
    }

    if (variant->type == CFL_VARIANT_KVLIST) {
        return kvlist_contains_variant(variant->data.as_kvlist, target, depth + 1);
    }

    return CFL_FALSE;
}

int cfl_container_array_contains_array(struct cfl_array *array,
                                       struct cfl_array *target)
{
    return array_contains_array(array, target, 0);
}

int cfl_container_array_contains_kvlist(struct cfl_array *array,
                                        struct cfl_kvlist *target)
{
    return array_contains_kvlist(array, target, 0);
}

int cfl_container_array_contains_variant(struct cfl_array *array,
                                         struct cfl_variant *target)
{
    return array_contains_variant(array, target, 0);
}

int cfl_container_kvlist_contains_array(struct cfl_kvlist *kvlist,
                                        struct cfl_array *target)
{
    return kvlist_contains_array(kvlist, target, 0);
}

int cfl_container_kvlist_contains_kvlist(struct cfl_kvlist *kvlist,
                                         struct cfl_kvlist *target)
{
    return kvlist_contains_kvlist(kvlist, target, 0);
}

int cfl_container_kvlist_contains_variant(struct cfl_kvlist *kvlist,
                                          struct cfl_variant *target)
{
    return kvlist_contains_variant(kvlist, target, 0);
}

int cfl_container_variant_contains_array(struct cfl_variant *variant,
                                         struct cfl_array *target)
{
    return variant_contains_array(variant, target, 0);
}

int cfl_container_variant_contains_kvlist(struct cfl_variant *variant,
                                          struct cfl_kvlist *target)
{
    return variant_contains_kvlist(variant, target, 0);
}

int cfl_container_variant_contains_variant(struct cfl_variant *variant,
                                           struct cfl_variant *target)
{
    return variant_contains_variant(variant, target, 0);
}
