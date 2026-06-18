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

static int parent_chain_contains_array(struct cfl_array *array,
                                       struct cfl_kvlist *kvlist,
                                       struct cfl_array *target)
{
    struct cfl_array *next_array;
    struct cfl_kvlist *next_kvlist;
    size_t depth;

    depth = 0;

    while (array != NULL || kvlist != NULL) {
        if (depth_exceeded(depth)) {
            return CFL_TRUE;
        }

        next_array = NULL;
        next_kvlist = NULL;

        if (array != NULL) {
            if (array == target) {
                return CFL_TRUE;
            }

            next_array = array->parent_array;
            next_kvlist = array->parent_kvlist;
        }
        else {
            next_array = kvlist->parent_array;
            next_kvlist = kvlist->parent_kvlist;
        }

        array = next_array;
        kvlist = next_kvlist;
        depth++;
    }

    return CFL_FALSE;
}

static int parent_chain_contains_kvlist(struct cfl_array *array,
                                        struct cfl_kvlist *kvlist,
                                        struct cfl_kvlist *target)
{
    struct cfl_array *next_array;
    struct cfl_kvlist *next_kvlist;
    size_t depth;

    depth = 0;

    while (array != NULL || kvlist != NULL) {
        if (depth_exceeded(depth)) {
            return CFL_TRUE;
        }

        next_array = NULL;
        next_kvlist = NULL;

        if (kvlist != NULL) {
            if (kvlist == target) {
                return CFL_TRUE;
            }

            next_array = kvlist->parent_array;
            next_kvlist = kvlist->parent_kvlist;
        }
        else {
            next_array = array->parent_array;
            next_kvlist = array->parent_kvlist;
        }

        array = next_array;
        kvlist = next_kvlist;
        depth++;
    }

    return CFL_FALSE;
}

static int claim_variant_container(struct cfl_variant *variant)
{
    if (variant->type == CFL_VARIANT_ARRAY) {
        if (variant->data.as_array != NULL &&
            cfl_container_claim_array(variant->data.as_array, variant) != 0) {
            return -1;
        }
    }

    if (variant->type == CFL_VARIANT_KVLIST) {
        if (variant->data.as_kvlist != NULL &&
            cfl_container_claim_kvlist(variant->data.as_kvlist, variant) != 0) {
            return -1;
        }
    }

    return 0;
}

int cfl_container_claim_array(struct cfl_array *array,
                              struct cfl_variant *owner)
{
    if (array == NULL || owner == NULL) {
        return -1;
    }

    if (array->owner != NULL && array->owner != owner) {
        return -1;
    }

    array->owner = owner;

    return 0;
}

int cfl_container_claim_kvlist(struct cfl_kvlist *kvlist,
                               struct cfl_variant *owner)
{
    if (kvlist == NULL || owner == NULL) {
        return -1;
    }

    if (kvlist->owner != NULL && kvlist->owner != owner) {
        return -1;
    }

    kvlist->owner = owner;

    return 0;
}

int cfl_container_adopt_variant(struct cfl_variant *variant)
{
    if (variant == NULL) {
        return -1;
    }

    if (variant->owned) {
        return -1;
    }

    if (claim_variant_container(variant) != 0) {
        return -1;
    }

    variant->owned = CFL_TRUE;

    return 0;
}

int cfl_container_move_variant_to_array(struct cfl_array *array,
                                        struct cfl_variant *variant)
{
    struct cfl_array *child_array;
    struct cfl_kvlist *child_kvlist;

    if (array == NULL || variant == NULL) {
        return -1;
    }

    if (variant->owned) {
        return -1;
    }

    if (variant->type == CFL_VARIANT_ARRAY) {
        child_array = variant->data.as_array;

        if (child_array != NULL &&
            parent_chain_contains_array(array, NULL, child_array)) {
            return -1;
        }
    }
    else if (variant->type == CFL_VARIANT_KVLIST) {
        child_kvlist = variant->data.as_kvlist;

        if (child_kvlist != NULL &&
            parent_chain_contains_kvlist(array, NULL, child_kvlist)) {
            return -1;
        }
    }

    if (claim_variant_container(variant) != 0) {
        return -1;
    }

    if (variant->type == CFL_VARIANT_ARRAY &&
        variant->data.as_array != NULL) {
        variant->data.as_array->parent_array = array;
        variant->data.as_array->parent_kvlist = NULL;
    }
    else if (variant->type == CFL_VARIANT_KVLIST &&
             variant->data.as_kvlist != NULL) {
        variant->data.as_kvlist->parent_array = array;
        variant->data.as_kvlist->parent_kvlist = NULL;
    }

    variant->owned = CFL_TRUE;

    return 0;
}

int cfl_container_move_variant_to_kvlist(struct cfl_kvlist *kvlist,
                                         struct cfl_variant *variant)
{
    struct cfl_array *child_array;
    struct cfl_kvlist *child_kvlist;

    if (kvlist == NULL || variant == NULL) {
        return -1;
    }

    if (variant->owned) {
        return -1;
    }

    if (variant->type == CFL_VARIANT_ARRAY) {
        child_array = variant->data.as_array;

        if (child_array != NULL &&
            parent_chain_contains_array(NULL, kvlist, child_array)) {
            return -1;
        }
    }
    else if (variant->type == CFL_VARIANT_KVLIST) {
        child_kvlist = variant->data.as_kvlist;

        if (child_kvlist != NULL &&
            parent_chain_contains_kvlist(NULL, kvlist, child_kvlist)) {
            return -1;
        }
    }

    if (claim_variant_container(variant) != 0) {
        return -1;
    }

    if (variant->type == CFL_VARIANT_ARRAY &&
        variant->data.as_array != NULL) {
        variant->data.as_array->parent_array = NULL;
        variant->data.as_array->parent_kvlist = kvlist;
    }
    else if (variant->type == CFL_VARIANT_KVLIST &&
             variant->data.as_kvlist != NULL) {
        variant->data.as_kvlist->parent_array = NULL;
        variant->data.as_kvlist->parent_kvlist = kvlist;
    }

    variant->owned = CFL_TRUE;

    return 0;
}

void cfl_container_release_variant(struct cfl_variant *variant)
{
    if (variant == NULL) {
        return;
    }

    variant->owned = CFL_FALSE;

    if (variant->type == CFL_VARIANT_ARRAY) {
        if (variant->data.as_array != NULL &&
            variant->data.as_array->owner == variant) {
            variant->data.as_array->owner = NULL;
            variant->data.as_array->parent_array = NULL;
            variant->data.as_array->parent_kvlist = NULL;
        }
    }
    else if (variant->type == CFL_VARIANT_KVLIST) {
        if (variant->data.as_kvlist != NULL &&
            variant->data.as_kvlist->owner == variant) {
            variant->data.as_kvlist->owner = NULL;
            variant->data.as_kvlist->parent_array = NULL;
            variant->data.as_kvlist->parent_kvlist = NULL;
        }
    }
}
