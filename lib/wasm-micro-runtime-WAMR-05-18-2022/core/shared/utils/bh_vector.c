/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_vector.h"

static uint8 *
alloc_vector_data(size_t length, size_t size_elem)
{
    uint64 total_size = ((uint64)size_elem) * length;
    uint8 *data;

    if (length > UINT32_MAX || size_elem > UINT32_MAX
        || total_size > UINT32_MAX) {
        return NULL;
    }

    if ((data = BH_MALLOC((uint32)total_size))) {
        memset(data, 0, (uint32)total_size);
    }

    return data;
}

static bool
extend_vector(Vector *vector, size_t length)
{
    uint8 *data;

    if (length <= vector->max_elems)
        return true;

    if (length < vector->size_elem * 3 / 2)
        length = vector->size_elem * 3 / 2;

    if (!(data = alloc_vector_data(length, vector->size_elem))) {
        return false;
    }

    if (vector->lock)
        os_mutex_lock(vector->lock);
    memcpy(data, vector->data, vector->size_elem * vector->max_elems);
    BH_FREE(vector->data);

    vector->data = data;
    vector->max_elems = length;
    if (vector->lock)
        os_mutex_unlock(vector->lock);
    return true;
}

bool
bh_vector_init(Vector *vector, size_t init_length, size_t size_elem,
               bool use_lock)
{
    if (!vector) {
        LOG_ERROR("Init vector failed: vector is NULL.\n");
        return false;
    }

    if (init_length == 0) {
        init_length = 4;
    }

    if (!(vector->data = alloc_vector_data(init_length, size_elem))) {
        LOG_ERROR("Init vector failed: alloc memory failed.\n");
        return false;
    }

    vector->size_elem = size_elem;
    vector->max_elems = init_length;
    vector->num_elems = 0;
    vector->lock = NULL;

    if (use_lock) {
        if (!(vector->lock = BH_MALLOC(sizeof(korp_mutex)))) {
            LOG_ERROR("Init vector failed: alloc locker failed.\n");
            bh_vector_destroy(vector);
            return false;
        }

        if (BHT_OK != os_mutex_init(vector->lock)) {
            LOG_ERROR("Init vector failed: init locker failed.\n");

            BH_FREE(vector->lock);
            vector->lock = NULL;

            bh_vector_destroy(vector);
            return false;
        }
    }

    return true;
}

bool
bh_vector_set(Vector *vector, uint32 index, const void *elem_buf)
{
    if (!vector || !elem_buf) {
        LOG_ERROR("Set vector elem failed: vector or elem buf is NULL.\n");
        return false;
    }

    if (index >= vector->num_elems) {
        LOG_ERROR("Set vector elem failed: invalid elem index.\n");
        return false;
    }

    if (vector->lock)
        os_mutex_lock(vector->lock);
    memcpy(vector->data + vector->size_elem * index, elem_buf,
           vector->size_elem);
    if (vector->lock)
        os_mutex_unlock(vector->lock);
    return true;
}

bool
bh_vector_get(Vector *vector, uint32 index, void *elem_buf)
{
    if (!vector || !elem_buf) {
        LOG_ERROR("Get vector elem failed: vector or elem buf is NULL.\n");
        return false;
    }

    if (index >= vector->num_elems) {
        LOG_ERROR("Get vector elem failed: invalid elem index.\n");
        return false;
    }

    if (vector->lock)
        os_mutex_lock(vector->lock);
    memcpy(elem_buf, vector->data + vector->size_elem * index,
           vector->size_elem);
    if (vector->lock)
        os_mutex_unlock(vector->lock);
    return true;
}

bool
bh_vector_insert(Vector *vector, uint32 index, const void *elem_buf)
{
    size_t i;
    uint8 *p;

    if (!vector || !elem_buf) {
        LOG_ERROR("Insert vector elem failed: vector or elem buf is NULL.\n");
        return false;
    }

    if (index >= vector->num_elems) {
        LOG_ERROR("Insert vector elem failed: invalid elem index.\n");
        return false;
    }

    if (!extend_vector(vector, vector->num_elems + 1)) {
        LOG_ERROR("Insert vector elem failed: extend vector failed.\n");
        return false;
    }

    if (vector->lock)
        os_mutex_lock(vector->lock);
    p = vector->data + vector->size_elem * vector->num_elems;
    for (i = vector->num_elems - 1; i > index; i--) {
        memcpy(p, p - vector->size_elem, vector->size_elem);
        p -= vector->size_elem;
    }

    memcpy(p, elem_buf, vector->size_elem);
    vector->num_elems++;
    if (vector->lock)
        os_mutex_unlock(vector->lock);
    return true;
}

bool
bh_vector_append(Vector *vector, const void *elem_buf)
{
    if (!vector || !elem_buf) {
        LOG_ERROR("Append vector elem failed: vector or elem buf is NULL.\n");
        return false;
    }

    if (!extend_vector(vector, vector->num_elems + 1)) {
        LOG_ERROR("Append ector elem failed: extend vector failed.\n");
        return false;
    }

    if (vector->lock)
        os_mutex_lock(vector->lock);
    memcpy(vector->data + vector->size_elem * vector->num_elems, elem_buf,
           vector->size_elem);
    vector->num_elems++;
    if (vector->lock)
        os_mutex_unlock(vector->lock);
    return true;
}

bool
bh_vector_remove(Vector *vector, uint32 index, void *old_elem_buf)
{
    uint32 i;
    uint8 *p;

    if (!vector) {
        LOG_ERROR("Remove vector elem failed: vector is NULL.\n");
        return false;
    }

    if (index >= vector->num_elems) {
        LOG_ERROR("Remove vector elem failed: invalid elem index.\n");
        return false;
    }

    if (vector->lock)
        os_mutex_lock(vector->lock);
    p = vector->data + vector->size_elem * index;

    if (old_elem_buf) {
        memcpy(old_elem_buf, p, vector->size_elem);
    }

    for (i = index; i < vector->num_elems - 1; i++) {
        memcpy(p, p + vector->size_elem, vector->size_elem);
        p += vector->size_elem;
    }

    vector->num_elems--;
    if (vector->lock)
        os_mutex_unlock(vector->lock);
    return true;
}

size_t
bh_vector_size(const Vector *vector)
{
    return vector ? vector->num_elems : 0;
}

bool
bh_vector_destroy(Vector *vector)
{
    if (!vector) {
        LOG_ERROR("Destroy vector elem failed: vector is NULL.\n");
        return false;
    }

    if (vector->data)
        BH_FREE(vector->data);

    if (vector->lock) {
        os_mutex_destroy(vector->lock);
        BH_FREE(vector->lock);
    }

    memset(vector, 0, sizeof(Vector));
    return true;
}
