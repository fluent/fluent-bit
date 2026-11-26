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

#include <cfl/cfl.h>
#include <cfl/cfl_container.h>
#include <cfl/cfl_view.h>

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>

/* Chunk size of the storage that holds the copies of a view. */
#define CFL_VIEW_STORAGE_CHUNK_SIZE  1024

void cfl_view_init(struct cfl_view *view)
{
    memset(view, 0, sizeof(struct cfl_view));
}

static void entry_drop_variant(struct cfl_view_entry *entry)
{
    if (entry->origin == CFL_VIEW_ENTRY_VARIANT) {
        cfl_variant_destroy(entry->value.data.as_variant);
        entry->value.data.as_variant = NULL;
    }
}

void cfl_view_release(struct cfl_view *view)
{
    size_t index;
    struct cfl_view_entry *entry;

    for (index = 0; index < view->count; index++) {
        entry = &view->entries[index];
        entry_drop_variant(entry);
    }

    /* nothing refers to the copies once the entries are gone */
    view->count = 0;
    if (view->storage != NULL) {
        cfl_arena_reset(view->storage);
    }
    view->release = CFL_FALSE;

    /* an empty view describes nothing: no commit can reach the old data */
    view->backend = NULL;
    view->context = NULL;
    view->modified = CFL_FALSE;
}

void cfl_view_destroy(struct cfl_view *view)
{
    cfl_view_release(view);
    if (view->storage != NULL) {
        cfl_arena_destroy(view->storage);
    }
    free(view->entries);
    memset(view, 0, sizeof(struct cfl_view));
}

int cfl_view_reserve(struct cfl_view *view, size_t capacity)
{
    struct cfl_view_entry *entries;

    if (capacity <= view->capacity) {
        return 0;
    }
    if (capacity > SIZE_MAX / sizeof(struct cfl_view_entry)) {
        return -1;
    }

    entries = realloc(view->entries, capacity * sizeof(struct cfl_view_entry));
    if (entries == NULL) {
        cfl_errno();
        return -1;
    }
    view->entries = entries;
    view->capacity = capacity;

    return 0;
}

/* 'size' bytes of the view storage, which is created on first use. */
static char *storage_alloc(struct cfl_view *view, size_t size)
{
    char *block;

    if (view->storage == NULL) {
        view->storage = cfl_arena_create(CFL_VIEW_STORAGE_CHUNK_SIZE);
        if (view->storage == NULL) {
            return NULL;
        }
    }

    block = cfl_arena_malloc(view->storage, size);
    if (block != NULL) {
        view->release = CFL_TRUE;
    }

    return block;
}

const char *cfl_view_store(struct cfl_view *view, const char *data, size_t size)
{
    char *copy;

    if (size == 0) {
        return "";
    }
    if (data == NULL) {
        return NULL;
    }

    copy = storage_alloc(view, size);
    if (copy != NULL) {
        memcpy(copy, data, size);
    }

    return copy;
}

/*
 * Room for one more entry. An append asks for it before it copies anything:
 * a copy cannot be taken back, and a call that fails must not leave one
 * behind in the storage.
 */
static int entry_room(struct cfl_view *view)
{
    if (view->count < view->capacity) {
        return 0;
    }

    return cfl_view_reserve(view, view->capacity ? view->capacity * 2 : 16);
}

/* Apply the ownership mode of the view to bytes received by an edit. */
static int edit_ref(struct cfl_view *view, const char *data, size_t size,
                    struct cfl_view_ref *out)
{
    if (size > 0 && data == NULL) {
        return -1;
    }

    if (view->copy) {
        data = cfl_view_store(view, data, size);
        if (data == NULL) {
            return -1;
        }
    }
    else if (size == 0) {
        data = "";
    }

    out->data = data;
    out->size = size;

    return 0;
}

static int edit_value(struct cfl_view *view, const struct cfl_view_value *value,
                      struct cfl_view_value *out)
{
    if (value == NULL) {
        return -1;
    }

    switch (value->type) {
    case CFL_VARIANT_STRING:
    case CFL_VARIANT_BYTES:
        out->type = value->type;
        return edit_ref(view, value->data.as_bytes.data, value->data.as_bytes.size,
                        &out->data.as_bytes);
    case CFL_VARIANT_BOOL:
    case CFL_VARIANT_INT:
    case CFL_VARIANT_UINT:
    case CFL_VARIANT_DOUBLE:
    case CFL_VARIANT_NULL:
    case CFL_VARIANT_REFERENCE:
        *out = *value;
        return 0;
    }

    /* containers and unknown types are not scalars */
    return -1;
}

/* Describe a CFL object the way a backend describes a source value. */
static void variant_read(struct cfl_variant *variant, struct cfl_view_value *out)
{
    memset(out, 0, sizeof(struct cfl_view_value));
    out->type = variant->type;

    switch (variant->type) {
    case CFL_VARIANT_STRING:
        out->data.as_bytes.data = variant->data.as_string;
        out->data.as_bytes.size = cfl_variant_size_get(variant);
        break;
    case CFL_VARIANT_BYTES:
        out->data.as_bytes.data = variant->data.as_bytes;
        out->data.as_bytes.size = cfl_variant_size_get(variant);
        break;
    case CFL_VARIANT_BOOL:
        out->data.as_bool = variant->data.as_bool ? 1 : 0;
        break;
    case CFL_VARIANT_INT:
        out->data.as_int64 = variant->data.as_int64;
        break;
    case CFL_VARIANT_UINT:
        out->data.as_uint64 = variant->data.as_uint64;
        break;
    case CFL_VARIANT_DOUBLE:
        out->data.as_double = variant->data.as_double;
        break;
    case CFL_VARIANT_REFERENCE:
        out->data.as_reference = variant->data.as_reference;
        break;
    case CFL_VARIANT_ARRAY:
    case CFL_VARIANT_KVLIST:
        out->data.as_variant = variant;
        break;
    default:
        break;
    }
}

int64_t cfl_view_find_ex(const struct cfl_view *view,
                         const char *key, size_t key_size,
                         enum cfl_kvlist_match_mode mode)
{
    size_t index;
    size_t offset;
    const struct cfl_view_entry *entry;

    if (mode == CFL_KVLIST_MATCH_CASE_SENSITIVE) {
        return cfl_view_find(view, key, key_size);
    }
    if (mode != CFL_KVLIST_MATCH_CASE_INSENSITIVE) {
        return -1;
    }

    for (index = 0; index < view->count; index++) {
        entry = &view->entries[index];
        if (entry->key.size != key_size) {
            continue;
        }
        for (offset = 0; offset < key_size; offset++) {
            if (tolower((unsigned char) entry->key.data[offset]) !=
                tolower((unsigned char) key[offset])) {
                break;
            }
        }
        if (offset == key_size) {
            return (int64_t) index;
        }
    }

    return -1;
}

int cfl_view_value_at(struct cfl_view *view, size_t index,
                      struct cfl_view_value *out)
{
    struct cfl_view_entry *entry;

    if (index >= view->count) {
        return -1;
    }

    entry = &view->entries[index];
    if (entry->origin == CFL_VIEW_ENTRY_LITERAL) {
        *out = entry->value;
        return 0;
    }
    if (entry->origin == CFL_VIEW_ENTRY_VARIANT) {
        variant_read(entry->value.data.as_variant, out);
        return 0;
    }
    if (view->backend == NULL || view->backend->value == NULL) {
        return -1;
    }

    memset(out, 0, sizeof(struct cfl_view_value));

    return view->backend->value(view, entry, out);
}

int cfl_view_get(struct cfl_view *view, const char *key, size_t key_size,
                 struct cfl_view_value *out)
{
    int64_t index;

    index = cfl_view_find(view, key, key_size);
    if (index < 0) {
        return 0;
    }
    if (cfl_view_value_at(view, (size_t) index, out) != 0) {
        return -1;
    }

    return 1;
}

int cfl_view_append(struct cfl_view *view, const char *key, size_t key_size,
                    const struct cfl_view_value *value)
{
    char *block;
    size_t value_size;
    const char *value_data;
    struct cfl_view_ref name;
    struct cfl_view_value literal;
    struct cfl_view_entry *entry;

    if (value == NULL || (key_size > 0 && key == NULL) || entry_room(view) != 0) {
        return -1;
    }

    if (view->copy &&
        (value->type == CFL_VARIANT_STRING || value->type == CFL_VARIANT_BYTES)) {
        /* the key and the value in one allocation: both are copied or none */
        value_data = value->data.as_bytes.data;
        value_size = value->data.as_bytes.size;
        if ((value_size > 0 && value_data == NULL) || key_size > SIZE_MAX - value_size) {
            return -1;
        }

        block = NULL;
        if (key_size + value_size > 0) {
            block = storage_alloc(view, key_size + value_size);
            if (block == NULL) {
                return -1;
            }
        }
        name.data = "";
        name.size = key_size;
        if (key_size > 0) {
            memcpy(block, key, key_size);
            name.data = block;
        }
        literal.type = value->type;
        literal.data.as_bytes.data = "";
        literal.data.as_bytes.size = value_size;
        if (value_size > 0) {
            memcpy(block + key_size, value_data, value_size);
            literal.data.as_bytes.data = block + key_size;
        }
    }
    else if (edit_value(view, value, &literal) != 0 ||
             edit_ref(view, key, key_size, &name) != 0) {
        /* the key is the only copy these make, and the last thing to fail */
        return -1;
    }

    entry = cfl_view_next_entry(view);
    entry->key = name;
    entry->origin = CFL_VIEW_ENTRY_LITERAL;
    entry->key_changed = CFL_FALSE;
    entry->source.pointer = NULL;
    entry->value = literal;
    view->modified = CFL_TRUE;

    return 0;
}

int cfl_view_set_at(struct cfl_view *view, size_t index,
                    const struct cfl_view_value *value)
{
    struct cfl_view_value literal;
    struct cfl_view_entry *entry;

    if (index >= view->count || edit_value(view, value, &literal) != 0) {
        return -1;
    }

    /* The pair stops referring to the original data, which stays untouched. */
    entry = &view->entries[index];
    entry_drop_variant(entry);
    entry->origin = CFL_VIEW_ENTRY_LITERAL;
    entry->key_changed = CFL_FALSE;
    entry->source.pointer = NULL;
    entry->value = literal;
    view->modified = CFL_TRUE;

    return 0;
}

static void entry_set_variant(struct cfl_view *view, struct cfl_view_entry *entry,
                              struct cfl_variant *value)
{
    entry->origin = CFL_VIEW_ENTRY_VARIANT;
    entry->key_changed = CFL_FALSE;
    entry->source.pointer = NULL;
    entry->value.type = value->type;
    entry->value.data.as_variant = value;
    view->modified = CFL_TRUE;
    view->release = CFL_TRUE;
}

int cfl_view_append_variant(struct cfl_view *view, const char *key, size_t key_size,
                            struct cfl_variant *value)
{
    struct cfl_view_ref name;
    struct cfl_view_entry *entry;

    if (value == NULL || (key_size > 0 && key == NULL) || entry_room(view) != 0) {
        return -1;
    }
    if (cfl_container_adopt_variant(value) != 0) {
        return -1;
    }
    /* the key is copied last: nothing after it can fail */
    if (edit_ref(view, key, key_size, &name) != 0) {
        cfl_container_release_variant(value);
        return -1;
    }

    entry = cfl_view_next_entry(view);
    entry->key = name;
    entry_set_variant(view, entry, value);

    return 0;
}

int cfl_view_set_variant_at(struct cfl_view *view, size_t index,
                            struct cfl_variant *value)
{
    struct cfl_view_entry *entry;

    if (index >= view->count || value == NULL) {
        return -1;
    }
    if (cfl_container_adopt_variant(value) != 0) {
        return -1;
    }

    entry = &view->entries[index];
    entry_drop_variant(entry);
    entry_set_variant(view, entry, value);

    return 0;
}

/* Undo the wrapping of a raw container that could not be appended. */
static void wrapper_discard(struct cfl_variant *wrapper)
{
    cfl_container_release_variant(wrapper);
    if (wrapper->type == CFL_VARIANT_ARRAY) {
        wrapper->data.as_array = NULL;
    }
    else {
        wrapper->data.as_kvlist = NULL;
    }
    cfl_variant_destroy(wrapper);
}

int cfl_view_append_array(struct cfl_view *view, const char *key, size_t key_size,
                          struct cfl_array *value)
{
    struct cfl_variant *wrapper;

    if (value == NULL) {
        return -1;
    }

    wrapper = cfl_variant_create_from_array_in(value->arena, value);
    if (wrapper == NULL) {
        return -1;
    }
    if (cfl_view_append_variant(view, key, key_size, wrapper) != 0) {
        wrapper_discard(wrapper);
        return -1;
    }

    return 0;
}

int cfl_view_append_kvlist(struct cfl_view *view, const char *key, size_t key_size,
                           struct cfl_kvlist *value)
{
    struct cfl_variant *wrapper;

    if (value == NULL) {
        return -1;
    }

    wrapper = cfl_variant_create_from_kvlist_in(value->arena, value);
    if (wrapper == NULL) {
        return -1;
    }
    if (cfl_view_append_variant(view, key, key_size, wrapper) != 0) {
        wrapper_discard(wrapper);
        return -1;
    }

    return 0;
}

int cfl_view_rename_at(struct cfl_view *view, size_t index,
                       const char *key, size_t key_size)
{
    struct cfl_view_ref name;
    struct cfl_view_entry *entry;

    if (index >= view->count || edit_ref(view, key, key_size, &name) != 0) {
        return -1;
    }

    entry = &view->entries[index];
    entry->key = name;
    if (entry->origin == CFL_VIEW_ENTRY_SOURCE) {
        entry->key_changed = CFL_TRUE;
    }
    view->modified = CFL_TRUE;

    return 0;
}

int cfl_view_remove_at(struct cfl_view *view, size_t index)
{
    if (index >= view->count) {
        return -1;
    }

    entry_drop_variant(&view->entries[index]);
    memmove(&view->entries[index], &view->entries[index + 1],
            (view->count - index - 1) * sizeof(struct cfl_view_entry));
    view->count--;
    view->modified = CFL_TRUE;

    return 0;
}

/* Materialization */

static struct cfl_variant *literal_variant(struct cfl_arena *arena,
                                           const struct cfl_view_value *value)
{
    const char *data;

    switch (value->type) {
    case CFL_VARIANT_STRING:
        data = value->data.as_bytes.size > 0 ? value->data.as_bytes.data : "";
        return cfl_variant_create_from_string_s_in(arena, (char *) data,
                                                   value->data.as_bytes.size, CFL_FALSE);
    case CFL_VARIANT_BYTES:
        data = value->data.as_bytes.size > 0 ? value->data.as_bytes.data : "";
        return cfl_variant_create_from_bytes_in(arena, (char *) data,
                                                value->data.as_bytes.size, CFL_FALSE);
    case CFL_VARIANT_BOOL:
        return cfl_variant_create_from_bool_in(arena, value->data.as_bool);
    case CFL_VARIANT_INT:
        return cfl_variant_create_from_int64_in(arena, value->data.as_int64);
    case CFL_VARIANT_UINT:
        return cfl_variant_create_from_uint64_in(arena, value->data.as_uint64);
    case CFL_VARIANT_DOUBLE:
        return cfl_variant_create_from_double_in(arena, value->data.as_double);
    case CFL_VARIANT_NULL:
        return cfl_variant_create_from_null_in(arena);
    case CFL_VARIANT_REFERENCE:
        return cfl_variant_create_from_reference_in(arena, value->data.as_reference);
    }

    return NULL;
}

static struct cfl_variant *variant_clone(struct cfl_arena *arena,
                                         struct cfl_variant *source);

static struct cfl_variant *kvlist_clone(struct cfl_arena *arena,
                                        struct cfl_kvlist *source)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *value;

    kvlist = cfl_kvlist_create_in(arena);
    if (kvlist == NULL) {
        return NULL;
    }

    cfl_list_foreach(head, &source->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        value = variant_clone(arena, pair->val);
        if (value == NULL) {
            cfl_kvlist_destroy(kvlist);
            return NULL;
        }
        if (cfl_kvlist_insert_s(kvlist, pair->key, cfl_sds_len(pair->key), value) != 0) {
            cfl_variant_destroy(value);
            cfl_kvlist_destroy(kvlist);
            return NULL;
        }
    }

    value = cfl_variant_create_from_kvlist_in(arena, kvlist);
    if (value == NULL) {
        cfl_kvlist_destroy(kvlist);
    }

    return value;
}

static struct cfl_variant *array_clone(struct cfl_arena *arena,
                                       struct cfl_array *source)
{
    size_t index;
    struct cfl_array *array;
    struct cfl_variant *value;

    array = cfl_array_create_in(arena, source->entry_count);
    if (array == NULL) {
        return NULL;
    }

    for (index = 0; index < source->entry_count; index++) {
        value = variant_clone(arena, source->entries[index]);
        if (value == NULL) {
            cfl_array_destroy(array);
            return NULL;
        }
        if (cfl_array_append(array, value) != 0) {
            cfl_variant_destroy(value);
            cfl_array_destroy(array);
            return NULL;
        }
    }

    value = cfl_variant_create_from_array_in(arena, array);
    if (value == NULL) {
        cfl_array_destroy(array);
    }

    return value;
}

/* Deep copy of a CFL object into an arena, or into the heap when it is NULL. */
static struct cfl_variant *variant_clone(struct cfl_arena *arena,
                                         struct cfl_variant *source)
{
    if (source == NULL) {
        return NULL;
    }

    switch (source->type) {
    case CFL_VARIANT_STRING:
        return cfl_variant_create_from_string_s_in(arena, source->data.as_string,
                                                   cfl_variant_size_get(source),
                                                   CFL_FALSE);
    case CFL_VARIANT_BYTES:
        return cfl_variant_create_from_bytes_in(arena, source->data.as_bytes,
                                                cfl_variant_size_get(source),
                                                CFL_FALSE);
    case CFL_VARIANT_BOOL:
        return cfl_variant_create_from_bool_in(arena, source->data.as_bool);
    case CFL_VARIANT_INT:
        return cfl_variant_create_from_int64_in(arena, source->data.as_int64);
    case CFL_VARIANT_UINT:
        return cfl_variant_create_from_uint64_in(arena, source->data.as_uint64);
    case CFL_VARIANT_DOUBLE:
        return cfl_variant_create_from_double_in(arena, source->data.as_double);
    case CFL_VARIANT_NULL:
        return cfl_variant_create_from_null_in(arena);
    case CFL_VARIANT_REFERENCE:
        return cfl_variant_create_from_reference_in(arena, source->data.as_reference);
    case CFL_VARIANT_ARRAY:
        if (source->data.as_array == NULL) {
            /* a variant created without its container stays without it */
            return cfl_variant_create_from_array_in(arena, NULL);
        }
        return array_clone(arena, source->data.as_array);
    case CFL_VARIANT_KVLIST:
        if (source->data.as_kvlist == NULL) {
            return cfl_variant_create_from_kvlist_in(arena, NULL);
        }
        return kvlist_clone(arena, source->data.as_kvlist);
    }

    return NULL;
}

/* Build an unattached variant from any entry, in the requested allocator. */
static struct cfl_variant *entry_variant(struct cfl_view *view,
                                         struct cfl_view_entry *entry,
                                         struct cfl_arena *arena)
{
    struct cfl_variant *value;
    struct cfl_variant *copy;

    if (entry->origin == CFL_VIEW_ENTRY_LITERAL) {
        return literal_variant(arena, &entry->value);
    }
    if (entry->origin == CFL_VIEW_ENTRY_VARIANT) {
        return variant_clone(arena, entry->value.data.as_variant);
    }
    if (view->backend == NULL || view->backend->materialize == NULL) {
        return NULL;
    }

    value = view->backend->materialize(view, entry);
    if (value == NULL || value->arena == arena) {
        return value;
    }

    /* backends build heap objects: move the result to the arena */
    copy = variant_clone(arena, value);
    cfl_variant_destroy(value);

    return copy;
}

struct cfl_kvlist *cfl_view_materialize_in(struct cfl_view *view,
                                           struct cfl_arena *arena)
{
    size_t index;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *value;
    struct cfl_view_entry *entry;

    kvlist = cfl_kvlist_create_in(arena);
    if (kvlist == NULL) {
        return NULL;
    }

    for (index = 0; index < view->count; index++) {
        entry = &view->entries[index];
        if (entry->key.size > INT_MAX) {
            cfl_kvlist_destroy(kvlist);
            return NULL;
        }

        value = entry_variant(view, entry, arena);
        if (value == NULL) {
            cfl_kvlist_destroy(kvlist);
            return NULL;
        }
        if (cfl_kvlist_insert_s(kvlist,
                                (char *) (entry->key.size > 0 ? entry->key.data : ""),
                                entry->key.size, value) != 0) {
            cfl_variant_destroy(value);
            cfl_kvlist_destroy(kvlist);
            return NULL;
        }
    }

    return kvlist;
}

struct cfl_kvlist *cfl_view_materialize(struct cfl_view *view)
{
    return cfl_view_materialize_in(view, NULL);
}

struct cfl_variant *cfl_view_materialize_at(struct cfl_view *view, size_t index)
{
    if (index >= view->count) {
        return NULL;
    }

    return entry_variant(view, &view->entries[index], NULL);
}

/* Native CFL backend */

static int kvlist_value(struct cfl_view *view, const struct cfl_view_entry *entry,
                        struct cfl_view_value *out)
{
    struct cfl_kvpair *pair;

    (void) view;
    pair = entry->source.pointer;
    if (pair->val == NULL) {
        return -1;
    }
    variant_read(pair->val, out);

    return 0;
}

static struct cfl_variant *kvlist_materialize(struct cfl_view *view,
                                              const struct cfl_view_entry *entry)
{
    struct cfl_kvpair *pair;

    (void) view;
    pair = entry->source.pointer;

    return variant_clone(NULL, pair->val);
}

static const struct cfl_view_backend kvlist_backend = {
    "cfl_kvlist",
    kvlist_value,
    kvlist_materialize,
};

int cfl_view_kvlist_load(struct cfl_view *view, struct cfl_kvlist *kvlist)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;

    if (kvlist == NULL) {
        return -1;
    }

    cfl_view_reset(view, &kvlist_backend, kvlist);
    cfl_list_foreach(head, &kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (cfl_view_load_pointer(view, pair->key, cfl_sds_len(pair->key), pair) != 0) {
            return -1;
        }
    }

    return 0;
}

/* Create the pair of a literal or variant entry at the tail of the list. */
static int kvlist_commit_entry(struct cfl_kvlist *kvlist, struct cfl_view_entry *entry)
{
    int result;
    char *key;
    struct cfl_variant *value;
    struct cfl_variant *owned;

    key = (char *) (entry->key.size > 0 ? entry->key.data : "");

    if (entry->origin == CFL_VIEW_ENTRY_VARIANT) {
        /* hand the object over, through a copy when the allocators differ */
        owned = entry->value.data.as_variant;
        if (owned->arena == kvlist->arena) {
            value = owned;
            cfl_container_release_variant(value);
        }
        else {
            value = variant_clone(kvlist->arena, owned);
            if (value == NULL) {
                return -1;
            }
        }

        result = cfl_kvlist_insert_s(kvlist, key, entry->key.size, value);
        if (result != 0) {
            if (value == owned) {
                cfl_container_adopt_variant(owned);
            }
            else {
                cfl_variant_destroy(value);
            }
            return -1;
        }
        if (value != owned) {
            cfl_variant_destroy(owned);
        }

        return 0;
    }

    value = literal_variant(kvlist->arena, &entry->value);
    if (value == NULL) {
        return -1;
    }
    if (cfl_kvlist_insert_s(kvlist, key, entry->key.size, value) != 0) {
        cfl_variant_destroy(value);
        return -1;
    }

    return 0;
}

/* Free the renamed keys a commit staged and could not install. */
static void kvlist_commit_unstage(struct cfl_view *view)
{
    size_t index;
    struct cfl_view_entry *entry;

    for (index = 0; index < view->count; index++) {
        entry = &view->entries[index];
        if (entry->origin == CFL_VIEW_ENTRY_SOURCE && entry->key_changed &&
            entry->cache.data != NULL) {
            cfl_sds_destroy((cfl_sds_t) entry->cache.data);
            entry->cache.data = NULL;
        }
    }
}

int cfl_view_kvlist_commit(struct cfl_view *view)
{
    size_t index;
    cfl_sds_t staged;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cfl_list *anchor;
    struct cfl_kvpair *pair;
    struct cfl_kvlist *kvlist;
    struct cfl_view_entry *entry;

    if (view->backend != &kvlist_backend) {
        return -1;
    }
    if (!view->modified) {
        return 0;
    }

    kvlist = view->context;

    /*
     * Stage every renamed key first, next to the key it replaces. The keys of
     * the list stay as they are until every edit has read what it borrows:
     * a new key or a new pair may be named after bytes of a key that is
     * renamed in this same commit.
     */
    for (index = 0; index < view->count; index++) {
        entry = &view->entries[index];
        if (entry->origin == CFL_VIEW_ENTRY_SOURCE && entry->key_changed) {
            entry->cache.data = NULL;
        }
    }
    for (index = 0; index < view->count; index++) {
        entry = &view->entries[index];
        if (entry->origin == CFL_VIEW_ENTRY_SOURCE && entry->key_changed) {
            pair = entry->source.pointer;
            if (entry->key.size > INT_MAX) {
                kvlist_commit_unstage(view);
                return -1;
            }
            staged = cfl_sds_create_len_in(pair->arena,
                                           entry->key.size > 0 ? entry->key.data : "",
                                           (int) entry->key.size);
            if (staged == NULL) {
                kvlist_commit_unstage(view);
                return -1;
            }
            entry->cache.data = staged;
        }
    }

    /*
     * Create the pairs of the other entries at the position they have in the
     * view. The pairs they replace are still in the list: a replaced value
     * keeps borrowing its key from the old pair until the new one exists.
     */
    anchor = &kvlist->list;
    for (index = 0; index < view->count; index++) {
        entry = &view->entries[index];
        if (entry->origin == CFL_VIEW_ENTRY_SOURCE) {
            pair = entry->source.pointer;
            anchor = &pair->_head;
            continue;
        }
        if (entry->key.size > INT_MAX || kvlist_commit_entry(kvlist, entry) != 0) {
            /* the renames stay pending, with the keys they borrow intact */
            kvlist_commit_unstage(view);
            return -1;
        }
        pair = cfl_list_entry_last(&kvlist->list, struct cfl_kvpair, _head);
        cfl_list_del(&pair->_head);
        __cfl_list_add(&pair->_head, anchor, anchor->next);
        anchor = &pair->_head;

        /* the pair is part of the list from here on */
        entry->origin = CFL_VIEW_ENTRY_SOURCE;
        entry->key.data = pair->key;
        entry->key_changed = CFL_FALSE;
        entry->source.pointer = pair;
    }

    /* Nothing borrows from the old keys anymore, and nothing can fail. */
    for (index = 0; index < view->count; index++) {
        entry = &view->entries[index];
        if (entry->origin == CFL_VIEW_ENTRY_SOURCE && entry->key_changed) {
            pair = entry->source.pointer;
            cfl_sds_destroy(pair->key);
            pair->key = (cfl_sds_t) entry->cache.data;
            /* the key now lives in the list, like every other source key */
            entry->key.data = pair->key;
            entry->key_changed = CFL_FALSE;
            entry->cache.data = NULL;
        }
    }

    /*
     * Every entry is a pair of the list now, in the same relative order, so
     * one pass pairs them up. A pair without an entry was removed or replaced.
     */
    index = 0;
    cfl_list_foreach_safe(head, tmp, &kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (index < view->count && view->entries[index].source.pointer == pair) {
            index++;
            continue;
        }
        cfl_kvpair_destroy(pair);
    }
    view->modified = CFL_FALSE;

    return 0;
}
