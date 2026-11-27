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

#ifndef CFL_VIEW_H
#define CFL_VIEW_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cfl/cfl_variant.h>
#include <cfl/cfl_array.h>
#include <cfl/cfl_kvlist.h>
#include <cfl/cfl_arena.h>

/*
 * EXPERIMENTAL: map views
 * =======================
 * A view is a performance optimization for high-load environments where
 * transforming key/value data is on the hot path. It gives the logical
 * interface of a string-keyed map over data that stays where it already is:
 * the bytes it arrived in, another library's objects, or a native
 * cfl_kvlist. Pairs are looked up and edited without building a CFL object
 * for each of them. Nothing here replaces cfl_kvlist; a view can always be
 * materialized into one.
 *
 * This interface is experimental: names, layouts and semantics can change in
 * any release until this notice is removed. VIEW.md has the full guide.
 *
 * Model
 * -----
 * The backend that owns the data loads one entry per pair: a borrowed key and
 * an opaque source handle. Values are not decoded at load time. Lookups and
 * edits then run on that entry table without backend calls:
 *
 *  - a source entry still refers to the pair in the original data;
 *  - a literal entry carries a scalar set through this interface;
 *  - a variant entry carries a CFL object set through this interface;
 *  - a removed pair simply has no entry.
 *
 * The original data is never written, so the entry table works as a
 * copy-on-write overlay. Whoever serializes the view walks the table: source
 * entries are transcoded or copied as raw spans, the others are encoded.
 *
 * Ownership and lifetime
 * ----------------------
 * - A view does not own the data it describes. The owner keeps it valid and
 *   unmodified from load until the view is reset, reloaded or destroyed.
 * - Every cfl_view_ref is borrowed. By default the keys and the string or
 *   bytes values handed to an edit are not copied: they must stay valid until
 *   the view is reset. With cfl_view_copy_set() the view copies them into its
 *   own storage instead, which is released on reset.
 * - A view owns its entry table, its copies, and the variants handed to
 *   cfl_view_append_variant() and cfl_view_set_variant_at().
 * - A view is not thread safe. It can move between threads only together
 *   with its data, and never while a call is using it.
 */

struct cfl_view_ref {
    const char *data;
    size_t size;
};

/*
 * A value read without materialization. Scalars are returned in place. For
 * arrays and kvlists 'as_variant' is the CFL object when the view or its
 * backend holds one, and NULL when the container only exists in the source
 * format: use cfl_view_materialize_at() for those.
 */
struct cfl_view_value {
    int type;                              /* CFL_VARIANT_* */
    union {
        int as_bool;
        int64_t as_int64;
        uint64_t as_uint64;
        double as_double;
        void *as_reference;
        struct cfl_view_ref as_bytes;      /* string or bytes, borrowed */
        struct cfl_variant *as_variant;    /* array or kvlist, borrowed */
    } data;
};

#define CFL_VIEW_ENTRY_SOURCE   0
#define CFL_VIEW_ENTRY_LITERAL  1
#define CFL_VIEW_ENTRY_VARIANT  2

struct cfl_view_entry {
    struct cfl_view_ref key;
    int origin;                            /* CFL_VIEW_ENTRY_* */
    int key_changed;                       /* source entry with a new key */
    union {
        int64_t index;
        void *pointer;
    } source;                              /* backend handle of the pair */
    struct cfl_view_ref cache;             /* backend private, source entries only */
    struct cfl_view_value value;           /* literal and variant entries only */
};

struct cfl_view;

/*
 * What a data source implements. Both callbacks receive source entries only.
 * A backend that cannot provide one of them leaves it NULL; the matching
 * calls then fail for its source entries.
 */
struct cfl_view_backend {
    const char *name;

    /* Read a source value. Scalars are returned without allocating. */
    int (*value) (struct cfl_view *view, const struct cfl_view_entry *entry,
                  struct cfl_view_value *out);

    /* Build an owned heap variant from a source value, nested data included. */
    struct cfl_variant *(*materialize) (struct cfl_view *view,
                                        const struct cfl_view_entry *entry);
};

struct cfl_view {
    const struct cfl_view_backend *backend;
    void *context;                         /* backend data for this load */
    struct cfl_view_entry *entries;
    size_t count;
    size_t capacity;
    int modified;
    int copy;                              /* copy the keys and values of edits */
    int release;                           /* reset has copies or variants to free */
    struct cfl_arena *storage;             /* copies, created on first use */
};

void cfl_view_init(struct cfl_view *view);
void cfl_view_destroy(struct cfl_view *view);
int cfl_view_reserve(struct cfl_view *view, size_t capacity);

/*
 * Free the copies and the variants of the current load and leave the view
 * empty and detached from the data it described: pending edits are dropped
 * and a commit has nothing to write. The entry table and the copy mode are
 * kept. cfl_view_reset() calls it when there is something to free.
 */
void cfl_view_release(struct cfl_view *view);

/*
 * Choose what edits do with the keys and the string or bytes values they
 * receive: borrow them (the default, enabled = 0) or copy them into storage
 * owned by the view. The choice applies to the edits made after the call.
 */
static inline void cfl_view_copy_set(struct cfl_view *view, int enabled)
{
    view->copy = enabled ? 1 : 0;
}

/*
 * Copy bytes into the storage of the view and return the copy, which stays
 * valid until the view is reset or destroyed. Returns NULL on failure.
 */
const char *cfl_view_store(struct cfl_view *view, const char *data, size_t size);

/* Start a new load, keeping the entry table allocation. */
static inline void cfl_view_reset(struct cfl_view *view,
                                  const struct cfl_view_backend *backend,
                                  void *context)
{
    if (view->release) {
        cfl_view_release(view);
    }
    view->backend = backend;
    view->context = context;
    view->count = 0;
    view->modified = 0;
}

static inline struct cfl_view_entry *cfl_view_next_entry(struct cfl_view *view)
{
    if (view->count == view->capacity &&
        cfl_view_reserve(view, view->capacity ? view->capacity * 2 : 16) != 0) {
        return NULL;
    }

    return &view->entries[view->count++];
}

/* Backend side: declare a pair of the original data. */
static inline int cfl_view_load_index(struct cfl_view *view,
                                      const char *key, size_t key_size,
                                      int64_t index)
{
    struct cfl_view_entry *entry;

    entry = cfl_view_next_entry(view);
    if (entry == NULL) {
        return -1;
    }
    entry->key.data = key;
    entry->key.size = key_size;
    entry->origin = CFL_VIEW_ENTRY_SOURCE;
    entry->key_changed = 0;
    entry->source.index = index;

    return 0;
}

static inline int cfl_view_load_pointer(struct cfl_view *view,
                                        const char *key, size_t key_size,
                                        void *pointer)
{
    struct cfl_view_entry *entry;

    entry = cfl_view_next_entry(view);
    if (entry == NULL) {
        return -1;
    }
    entry->key.data = key;
    entry->key.size = key_size;
    entry->origin = CFL_VIEW_ENTRY_SOURCE;
    entry->key_changed = 0;
    entry->source.pointer = pointer;

    return 0;
}

static inline size_t cfl_view_count(const struct cfl_view *view)
{
    return view->count;
}

static inline int cfl_view_modified(const struct cfl_view *view)
{
    return view->modified;
}

static inline const struct cfl_view_entry *cfl_view_entry_at(const struct cfl_view *view,
                                                             size_t index)
{
    return index < view->count ? &view->entries[index] : NULL;
}

/*
 * Position of the first pair with exactly this key, or -1. Keys are compared
 * byte by byte; use cfl_view_find_ex() to ignore ASCII case, which is what
 * cfl_kvlist_fetch() does.
 */
static inline int64_t cfl_view_find(const struct cfl_view *view,
                                    const char *key, size_t key_size)
{
    size_t index;

    for (index = 0; index < view->count; index++) {
        if (view->entries[index].key.size == key_size &&
            memcmp(view->entries[index].key.data, key, key_size) == 0) {
            return (int64_t) index;
        }
    }

    return -1;
}

int64_t cfl_view_find_ex(const struct cfl_view *view,
                         const char *key, size_t key_size,
                         enum cfl_kvlist_match_mode mode);

/* Read the value at a position. Returns 0, or -1 when it cannot be read. */
int cfl_view_value_at(struct cfl_view *view, size_t index,
                      struct cfl_view_value *out);

/* Find and read in one call. Returns 1 when found, 0 when missing, -1 on error. */
int cfl_view_get(struct cfl_view *view, const char *key, size_t key_size,
                 struct cfl_view_value *out);

/*
 * Edits
 * -----
 * Positions are the ones cfl_view_find() and cfl_view_entry_at() use. Append
 * does not check for duplicates. Every edit returns 0 on success and -1 on
 * failure, and a failed edit leaves the view as it was.
 *
 * cfl_view_append() and cfl_view_set_at() accept every scalar type: bool,
 * int, uint, double, null, reference, string and bytes. Arrays and kvlists
 * go through the variant calls.
 */
int cfl_view_append(struct cfl_view *view, const char *key, size_t key_size,
                    const struct cfl_view_value *value);

/* Replace the value at a position, keeping the key and the position. */
int cfl_view_set_at(struct cfl_view *view, size_t index,
                    const struct cfl_view_value *value);

/*
 * Append or set a CFL object of any type. The view takes ownership of the
 * variant on success and destroys it when the pair is removed or replaced,
 * or when the view is reset. The variant must not belong to a container. An
 * arena variant is accepted as long as its arena outlives the entry.
 */
int cfl_view_append_variant(struct cfl_view *view, const char *key, size_t key_size,
                            struct cfl_variant *value);
int cfl_view_set_variant_at(struct cfl_view *view, size_t index,
                            struct cfl_variant *value);

/* Same for a raw array or kvlist, which is owned by the view on success. */
int cfl_view_append_array(struct cfl_view *view, const char *key, size_t key_size,
                          struct cfl_array *value);
int cfl_view_append_kvlist(struct cfl_view *view, const char *key, size_t key_size,
                           struct cfl_kvlist *value);

/* Replace the key at a position, keeping the value and the position. */
int cfl_view_rename_at(struct cfl_view *view, size_t index,
                       const char *key, size_t key_size);

/* Remove the pair at a position, keeping the order of the others. */
int cfl_view_remove_at(struct cfl_view *view, size_t index);

static inline int cfl_view_append_string(struct cfl_view *view,
                                         const char *key, size_t key_size,
                                         const char *value, size_t value_size)
{
    struct cfl_view_value literal;

    literal.type = CFL_VARIANT_STRING;
    literal.data.as_bytes.data = value;
    literal.data.as_bytes.size = value_size;

    return cfl_view_append(view, key, key_size, &literal);
}

static inline int cfl_view_append_bytes(struct cfl_view *view,
                                        const char *key, size_t key_size,
                                        const char *value, size_t value_size)
{
    struct cfl_view_value literal;

    literal.type = CFL_VARIANT_BYTES;
    literal.data.as_bytes.data = value;
    literal.data.as_bytes.size = value_size;

    return cfl_view_append(view, key, key_size, &literal);
}

static inline int cfl_view_append_bool(struct cfl_view *view,
                                       const char *key, size_t key_size, int value)
{
    struct cfl_view_value literal;

    literal.type = CFL_VARIANT_BOOL;
    literal.data.as_bool = value ? 1 : 0;

    return cfl_view_append(view, key, key_size, &literal);
}

static inline int cfl_view_append_int64(struct cfl_view *view,
                                        const char *key, size_t key_size, int64_t value)
{
    struct cfl_view_value literal;

    literal.type = CFL_VARIANT_INT;
    literal.data.as_int64 = value;

    return cfl_view_append(view, key, key_size, &literal);
}

static inline int cfl_view_append_uint64(struct cfl_view *view,
                                         const char *key, size_t key_size, uint64_t value)
{
    struct cfl_view_value literal;

    literal.type = CFL_VARIANT_UINT;
    literal.data.as_uint64 = value;

    return cfl_view_append(view, key, key_size, &literal);
}

static inline int cfl_view_append_double(struct cfl_view *view,
                                         const char *key, size_t key_size, double value)
{
    struct cfl_view_value literal;

    literal.type = CFL_VARIANT_DOUBLE;
    literal.data.as_double = value;

    return cfl_view_append(view, key, key_size, &literal);
}

static inline int cfl_view_append_null(struct cfl_view *view,
                                       const char *key, size_t key_size)
{
    struct cfl_view_value literal;

    literal.type = CFL_VARIANT_NULL;
    literal.data.as_uint64 = 0;

    return cfl_view_append(view, key, key_size, &literal);
}

static inline int cfl_view_set_string_at(struct cfl_view *view, size_t index,
                                         const char *value, size_t value_size)
{
    struct cfl_view_value literal;

    literal.type = CFL_VARIANT_STRING;
    literal.data.as_bytes.data = value;
    literal.data.as_bytes.size = value_size;

    return cfl_view_set_at(view, index, &literal);
}

static inline int cfl_view_set_bytes_at(struct cfl_view *view, size_t index,
                                        const char *value, size_t value_size)
{
    struct cfl_view_value literal;

    literal.type = CFL_VARIANT_BYTES;
    literal.data.as_bytes.data = value;
    literal.data.as_bytes.size = value_size;

    return cfl_view_set_at(view, index, &literal);
}

static inline int cfl_view_set_bool_at(struct cfl_view *view, size_t index, int value)
{
    struct cfl_view_value literal;

    literal.type = CFL_VARIANT_BOOL;
    literal.data.as_bool = value ? 1 : 0;

    return cfl_view_set_at(view, index, &literal);
}

static inline int cfl_view_set_int64_at(struct cfl_view *view, size_t index,
                                        int64_t value)
{
    struct cfl_view_value literal;

    literal.type = CFL_VARIANT_INT;
    literal.data.as_int64 = value;

    return cfl_view_set_at(view, index, &literal);
}

static inline int cfl_view_set_uint64_at(struct cfl_view *view, size_t index,
                                         uint64_t value)
{
    struct cfl_view_value literal;

    literal.type = CFL_VARIANT_UINT;
    literal.data.as_uint64 = value;

    return cfl_view_set_at(view, index, &literal);
}

static inline int cfl_view_set_double_at(struct cfl_view *view, size_t index,
                                         double value)
{
    struct cfl_view_value literal;

    literal.type = CFL_VARIANT_DOUBLE;
    literal.data.as_double = value;

    return cfl_view_set_at(view, index, &literal);
}

static inline int cfl_view_set_null_at(struct cfl_view *view, size_t index)
{
    struct cfl_view_value literal;

    literal.type = CFL_VARIANT_NULL;
    literal.data.as_uint64 = 0;

    return cfl_view_set_at(view, index, &literal);
}

/*
 * Materialization
 * ---------------
 * The exit for code that needs native CFL objects. The results are owned by
 * the caller and independent of the view and of the data it describes, with
 * one exception: a CFL_VARIANT_REFERENCE value is the same pointer, and what
 * it points to has to outlive the object, like for any CFL reference.
 *
 * cfl_view_materialize() builds a kvlist with the current content of the
 * view. The '_in' form allocates it from an arena; NULL selects the heap.
 * cfl_view_materialize_at() builds a heap variant from one value.
 */
struct cfl_kvlist *cfl_view_materialize(struct cfl_view *view);
struct cfl_kvlist *cfl_view_materialize_in(struct cfl_view *view,
                                           struct cfl_arena *arena);
struct cfl_variant *cfl_view_materialize_at(struct cfl_view *view, size_t index);

/*
 * Native CFL backend
 * ------------------
 * Load a view over an existing cfl_kvlist. Keys and values are borrowed from
 * the list. cfl_view_kvlist_commit() writes the edits back to the same list:
 * pairs without an entry are destroyed, renamed pairs get the new key, and
 * the pairs added or replaced through the view are created at the position
 * they have in the view. After a successful commit every entry is a source
 * entry of the list again. A commit only fails when an allocation fails. It
 * can then leave the list with part of the edits applied, including both the
 * old and the new pair of a replaced value; the list and the view stay valid.
 */
int cfl_view_kvlist_load(struct cfl_view *view, struct cfl_kvlist *kvlist);
int cfl_view_kvlist_commit(struct cfl_view *view);

#endif
