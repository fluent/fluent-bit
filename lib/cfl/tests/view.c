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
#include <cfl/cfl_view.h>

#include "cfl_tests_internal.h"

#define KEY(text)  text, sizeof(text) - 1

/* Stop the test case when its setup fails: the checks after it need it. */
#define TEST_ASSERT(condition)       \
    do {                             \
        if (!TEST_CHECK(condition)) { \
            abort();                 \
        }                            \
    } while (0)

static int ref_is(const struct cfl_view_ref *ref, const char *text)
{
    return ref->size == strlen(text) && memcmp(ref->data, text, ref->size) == 0;
}

static void check_keys(struct cfl_kvlist *kvlist, const char **keys, size_t count)
{
    size_t index;
    struct cfl_list *head;
    struct cfl_kvpair *pair;

    index = 0;
    cfl_list_foreach(head, &kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (!TEST_CHECK(index < count)) {
            return;
        }
        TEST_CHECK(strcmp(pair->key, keys[index]) == 0);
        TEST_MSG("position %zu: got '%s', expected '%s'", index, pair->key, keys[index]);
        index++;
    }
    TEST_CHECK(index == count);
}

static struct cfl_kvlist *sample_kvlist(struct cfl_arena *arena)
{
    struct cfl_array *array;
    struct cfl_kvlist *nested;
    struct cfl_kvlist *kvlist;

    kvlist = cfl_kvlist_create_in(arena);
    TEST_ASSERT(kvlist != NULL);

    TEST_ASSERT(cfl_kvlist_insert_string(kvlist, "name", "checkout") == 0);
    TEST_ASSERT(cfl_kvlist_insert_int64(kvlist, "status", -200) == 0);
    TEST_ASSERT(cfl_kvlist_insert_uint64(kvlist, "bytes", 5120) == 0);
    TEST_ASSERT(cfl_kvlist_insert_double(kvlist, "ratio", 0.25) == 0);
    TEST_ASSERT(cfl_kvlist_insert_bool(kvlist, "ok", CFL_TRUE) == 0);
    TEST_ASSERT(cfl_kvlist_insert_bytes(kvlist, "blob", "\x00\x01\x02", 3, CFL_FALSE) == 0);

    array = cfl_array_create_in(arena, 2);
    TEST_ASSERT(array != NULL);
    TEST_ASSERT(cfl_array_append_string(array, "a") == 0);
    TEST_ASSERT(cfl_array_append_int64(array, 7) == 0);
    TEST_ASSERT(cfl_kvlist_insert_array(kvlist, "tags", array) == 0);

    nested = cfl_kvlist_create_in(arena);
    TEST_ASSERT(nested != NULL);
    TEST_ASSERT(cfl_kvlist_insert_string(nested, "zone", "a1") == 0);
    TEST_ASSERT(cfl_kvlist_insert_kvlist(kvlist, "cloud", nested) == 0);

    return kvlist;
}

static void kvlist_read(void)
{
    struct cfl_view view;
    struct cfl_view_value value;
    struct cfl_kvlist *kvlist;

    kvlist = sample_kvlist(NULL);
    cfl_view_init(&view);

    TEST_CHECK(cfl_view_kvlist_load(&view, kvlist) == 0);
    TEST_CHECK(cfl_view_count(&view) == 8);
    TEST_CHECK(cfl_view_modified(&view) == 0);
    TEST_CHECK(cfl_view_find(&view, KEY("name")) == 0);
    TEST_CHECK(cfl_view_find(&view, KEY("cloud")) == 7);
    TEST_CHECK(cfl_view_find(&view, KEY("missing")) == -1);
    TEST_CHECK(cfl_view_entry_at(&view, 8) == NULL);
    TEST_CHECK(ref_is(&cfl_view_entry_at(&view, 1)->key, "status"));

    TEST_CHECK(cfl_view_get(&view, KEY("name"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_STRING && ref_is(&value.data.as_bytes, "checkout"));
    TEST_CHECK(cfl_view_get(&view, KEY("status"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_INT && value.data.as_int64 == -200);
    TEST_CHECK(cfl_view_get(&view, KEY("bytes"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_UINT && value.data.as_uint64 == 5120);
    TEST_CHECK(cfl_view_get(&view, KEY("ratio"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_DOUBLE && value.data.as_double == 0.25);
    TEST_CHECK(cfl_view_get(&view, KEY("ok"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_BOOL && value.data.as_bool == 1);
    TEST_CHECK(cfl_view_get(&view, KEY("blob"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_BYTES && value.data.as_bytes.size == 3 &&
               memcmp(value.data.as_bytes.data, "\x00\x01\x02", 3) == 0);

    /* a native list holds its containers as CFL objects */
    TEST_CHECK(cfl_view_get(&view, KEY("tags"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_ARRAY && value.data.as_variant != NULL &&
               cfl_array_size(value.data.as_variant->data.as_array) == 2);
    TEST_CHECK(cfl_view_get(&view, KEY("cloud"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_KVLIST && value.data.as_variant != NULL);

    TEST_CHECK(cfl_view_get(&view, KEY("missing"), &value) == 0);
    TEST_CHECK(cfl_view_value_at(&view, 8, &value) == -1);

    cfl_view_destroy(&view);
    cfl_kvlist_destroy(kvlist);
}

static void find_modes(void)
{
    struct cfl_view view;
    struct cfl_kvlist *kvlist;

    kvlist = cfl_kvlist_create();
    TEST_ASSERT(kvlist != NULL);
    TEST_ASSERT(cfl_kvlist_insert_string(kvlist, "Host", "a") == 0);
    TEST_ASSERT(cfl_kvlist_insert_string(kvlist, "host", "b") == 0);

    cfl_view_init(&view);
    TEST_CHECK(cfl_view_kvlist_load(&view, kvlist) == 0);

    TEST_CHECK(cfl_view_find(&view, KEY("host")) == 1);
    TEST_CHECK(cfl_view_find(&view, KEY("HOST")) == -1);
    TEST_CHECK(cfl_view_find_ex(&view, KEY("host"), CFL_KVLIST_MATCH_CASE_SENSITIVE) == 1);
    TEST_CHECK(cfl_view_find_ex(&view, KEY("HOST"), CFL_KVLIST_MATCH_CASE_SENSITIVE) == -1);
    TEST_CHECK(cfl_view_find_ex(&view, KEY("HOST"), CFL_KVLIST_MATCH_CASE_INSENSITIVE) == 0);
    TEST_CHECK(cfl_view_find_ex(&view, KEY("hos"), CFL_KVLIST_MATCH_CASE_INSENSITIVE) == -1);
    TEST_CHECK(cfl_view_find_ex(&view, KEY("host"), (enum cfl_kvlist_match_mode) 99) == -1);

    cfl_view_destroy(&view);
    cfl_kvlist_destroy(kvlist);
}

static void kvlist_edit_commit(void)
{
    struct cfl_view view;
    struct cfl_view_value value;
    struct cfl_variant *fetched;
    struct cfl_kvlist *kvlist;
    const char *expected[] = {"first", "renamed", "replaced", "last", "added"};

    kvlist = cfl_kvlist_create();
    TEST_ASSERT(kvlist != NULL);
    TEST_ASSERT(cfl_kvlist_insert_string(kvlist, "first", "1") == 0);
    TEST_ASSERT(cfl_kvlist_insert_string(kvlist, "old", "2") == 0);
    TEST_ASSERT(cfl_kvlist_insert_string(kvlist, "gone", "3") == 0);
    TEST_ASSERT(cfl_kvlist_insert_string(kvlist, "replaced", "4") == 0);
    TEST_ASSERT(cfl_kvlist_insert_string(kvlist, "last", "5") == 0);

    cfl_view_init(&view);
    TEST_CHECK(cfl_view_kvlist_load(&view, kvlist) == 0);

    /* an untouched view commits nothing */
    TEST_CHECK(cfl_view_kvlist_commit(&view) == 0);
    TEST_CHECK(cfl_kvlist_count(kvlist) == 5);

    TEST_CHECK(cfl_view_rename_at(&view, 1, KEY("renamed")) == 0);
    TEST_CHECK(cfl_view_remove_at(&view, 2) == 0);
    TEST_CHECK(cfl_view_set_int64_at(&view, 2, 44) == 0);
    TEST_CHECK(cfl_view_append_string(&view, KEY("added"), KEY("6")) == 0);
    TEST_CHECK(cfl_view_modified(&view) != 0);
    TEST_CHECK(cfl_view_count(&view) == 5);

    /* the list is untouched until the commit */
    TEST_CHECK(cfl_kvlist_count(kvlist) == 5);
    TEST_CHECK(cfl_kvlist_fetch(kvlist, "gone") != NULL);

    /* edits are visible through the view right away */
    TEST_CHECK(cfl_view_get(&view, KEY("renamed"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_STRING && ref_is(&value.data.as_bytes, "2"));
    TEST_CHECK(cfl_view_get(&view, KEY("replaced"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_INT && value.data.as_int64 == 44);

    TEST_CHECK(cfl_view_kvlist_commit(&view) == 0);
    TEST_CHECK(cfl_view_modified(&view) == 0);
    check_keys(kvlist, expected, 5);

    fetched = cfl_kvlist_fetch(kvlist, "renamed");
    TEST_CHECK(fetched != NULL && fetched->type == CFL_VARIANT_STRING &&
               strcmp(fetched->data.as_string, "2") == 0);
    fetched = cfl_kvlist_fetch(kvlist, "replaced");
    TEST_CHECK(fetched != NULL && fetched->type == CFL_VARIANT_INT &&
               fetched->data.as_int64 == 44);
    fetched = cfl_kvlist_fetch(kvlist, "added");
    TEST_CHECK(fetched != NULL && strcmp(fetched->data.as_string, "6") == 0);

    /* every entry is a source entry again: a second round works the same way */
    TEST_CHECK(cfl_view_entry_at(&view, 4)->origin == CFL_VIEW_ENTRY_SOURCE);
    TEST_CHECK(cfl_view_remove_at(&view, 0) == 0);
    TEST_CHECK(cfl_view_kvlist_commit(&view) == 0);
    check_keys(kvlist, expected + 1, 4);

    cfl_view_destroy(&view);
    cfl_kvlist_destroy(kvlist);
}

static void literals(void)
{
    int marker;
    struct cfl_view view;
    struct cfl_view_value value;
    struct cfl_view_value container;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *fetched;

    cfl_view_init(&view);
    cfl_view_reset(&view, NULL, NULL);

    TEST_CHECK(cfl_view_append_string(&view, KEY("string"), KEY("text")) == 0);
    TEST_CHECK(cfl_view_append_bytes(&view, KEY("bytes"), "\x00\xff", 2) == 0);
    TEST_CHECK(cfl_view_append_bool(&view, KEY("bool"), 5) == 0);
    TEST_CHECK(cfl_view_append_int64(&view, KEY("int"), INT64_MIN) == 0);
    TEST_CHECK(cfl_view_append_uint64(&view, KEY("uint"), UINT64_MAX) == 0);
    TEST_CHECK(cfl_view_append_double(&view, KEY("double"), -1.5) == 0);
    TEST_CHECK(cfl_view_append_null(&view, KEY("null")) == 0);
    TEST_CHECK(cfl_view_append_string(&view, KEY(""), NULL, 0) == 0);

    value.type = CFL_VARIANT_REFERENCE;
    value.data.as_reference = &marker;
    TEST_CHECK(cfl_view_append(&view, KEY("reference"), &value) == 0);
    TEST_CHECK(cfl_view_count(&view) == 9);

    TEST_CHECK(cfl_view_get(&view, KEY("bool"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_BOOL && value.data.as_bool == 1);
    TEST_CHECK(cfl_view_get(&view, KEY("int"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_INT && value.data.as_int64 == INT64_MIN);
    TEST_CHECK(cfl_view_get(&view, KEY("uint"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_UINT && value.data.as_uint64 == UINT64_MAX);
    TEST_CHECK(cfl_view_get(&view, KEY("null"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_NULL);
    TEST_CHECK(cfl_view_get(&view, KEY(""), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_STRING && value.data.as_bytes.size == 0);

    /* typed replacement */
    TEST_CHECK(cfl_view_set_string_at(&view, 2, KEY("yes")) == 0);
    TEST_CHECK(cfl_view_set_bytes_at(&view, 0, "\x01", 1) == 0);
    TEST_CHECK(cfl_view_set_bool_at(&view, 3, 0) == 0);
    TEST_CHECK(cfl_view_set_uint64_at(&view, 5, 9) == 0);
    TEST_CHECK(cfl_view_set_double_at(&view, 4, 2.5) == 0);
    TEST_CHECK(cfl_view_set_null_at(&view, 1) == 0);
    TEST_CHECK(cfl_view_get(&view, KEY("bool"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_STRING && ref_is(&value.data.as_bytes, "yes"));

    /* containers are not scalars, and positions are checked */
    container.type = CFL_VARIANT_ARRAY;
    container.data.as_variant = NULL;
    TEST_CHECK(cfl_view_append(&view, KEY("array"), &container) == -1);
    TEST_CHECK(cfl_view_set_at(&view, 0, &container) == -1);
    TEST_CHECK(cfl_view_append(&view, KEY("none"), NULL) == -1);
    TEST_CHECK(cfl_view_append_string(&view, KEY("bad"), NULL, 4) == -1);
    TEST_CHECK(cfl_view_append_string(&view, NULL, 3, KEY("bad")) == -1);
    TEST_CHECK(cfl_view_set_int64_at(&view, 9, 1) == -1);
    TEST_CHECK(cfl_view_rename_at(&view, 9, KEY("x")) == -1);
    TEST_CHECK(cfl_view_remove_at(&view, 9) == -1);
    TEST_CHECK(cfl_view_count(&view) == 9);

    kvlist = cfl_view_materialize(&view);
    TEST_ASSERT(kvlist != NULL);
    TEST_CHECK(cfl_kvlist_count(kvlist) == 9);
    fetched = cfl_kvlist_fetch(kvlist, "string");
    TEST_CHECK(fetched != NULL && fetched->type == CFL_VARIANT_BYTES &&
               cfl_variant_size_get(fetched) == 1);
    fetched = cfl_kvlist_fetch(kvlist, "bytes");
    TEST_CHECK(fetched != NULL && fetched->type == CFL_VARIANT_NULL);
    fetched = cfl_kvlist_fetch(kvlist, "int");
    TEST_CHECK(fetched != NULL && fetched->type == CFL_VARIANT_BOOL &&
               fetched->data.as_bool == 0);
    fetched = cfl_kvlist_fetch(kvlist, "uint");
    TEST_CHECK(fetched != NULL && fetched->type == CFL_VARIANT_DOUBLE &&
               fetched->data.as_double == 2.5);
    fetched = cfl_kvlist_fetch(kvlist, "double");
    TEST_CHECK(fetched != NULL && fetched->type == CFL_VARIANT_UINT &&
               fetched->data.as_uint64 == 9);
    fetched = cfl_kvlist_fetch(kvlist, "reference");
    TEST_CHECK(fetched != NULL && fetched->type == CFL_VARIANT_REFERENCE &&
               fetched->data.as_reference == &marker);
    fetched = cfl_kvlist_fetch_s(kvlist, "", 0);
    TEST_CHECK(fetched != NULL && fetched->type == CFL_VARIANT_STRING &&
               cfl_variant_size_get(fetched) == 0);
    cfl_kvlist_destroy(kvlist);

    cfl_view_destroy(&view);
}

static void copy_mode(void)
{
    char key[8];
    char text[8];
    char name[8];
    struct cfl_view view;
    struct cfl_view_value value;
    const char *stored;
    size_t used;

    cfl_view_init(&view);
    cfl_view_reset(&view, NULL, NULL);

    /* borrowed by default: the view sees later changes to the buffers */
    memcpy(key, "alpha", 5);
    memcpy(text, "one", 3);
    TEST_CHECK(cfl_view_append_string(&view, key, 5, text, 3) == 0);
    TEST_CHECK(cfl_view_entry_at(&view, 0)->key.data == key);
    memcpy(text, "two", 3);
    TEST_CHECK(cfl_view_get(&view, KEY("alpha"), &value) == 1);
    TEST_CHECK(ref_is(&value.data.as_bytes, "two"));

    /* copied on request: the buffers can be reused right away */
    cfl_view_copy_set(&view, CFL_TRUE);
    memcpy(key, "bravo", 5);
    memcpy(text, "red", 3);
    TEST_CHECK(cfl_view_append_string(&view, key, 5, text, 3) == 0);
    memcpy(name, "charlie", 7);
    TEST_CHECK(cfl_view_rename_at(&view, 0, name, 7) == 0);
    TEST_CHECK(cfl_view_set_bytes_at(&view, 0, text, 3) == 0);
    memset(key, 'x', sizeof(key));
    memset(text, 'x', sizeof(text));
    memset(name, 'x', sizeof(name));

    TEST_CHECK(cfl_view_find(&view, KEY("charlie")) == 0);
    TEST_CHECK(cfl_view_get(&view, KEY("charlie"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_BYTES && ref_is(&value.data.as_bytes, "red"));
    TEST_CHECK(cfl_view_get(&view, KEY("bravo"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_STRING && ref_is(&value.data.as_bytes, "red"));

    /* a rejected append leaves no copy behind in the storage */
    used = cfl_arena_bytes_used(view.storage);
    value.type = CFL_VARIANT_STRING;
    value.data.as_bytes.data = text;
    value.data.as_bytes.size = sizeof(text);
    TEST_CHECK(cfl_view_append(&view, NULL, 4, &value) != 0);
    value.data.as_bytes.data = NULL;
    TEST_CHECK(cfl_view_append(&view, KEY("delta"), &value) != 0);
    value.type = CFL_VARIANT_ARRAY;
    TEST_CHECK(cfl_view_append(&view, KEY("delta"), &value) != 0);
    TEST_CHECK(cfl_view_append_variant(&view, KEY("delta"), NULL) != 0);
    TEST_CHECK(cfl_view_count(&view) == 2);
    TEST_CHECK(cfl_arena_bytes_used(view.storage) == used);

    /* empty keys and values are copied as empty */
    TEST_CHECK(cfl_view_append_string(&view, NULL, 0, NULL, 0) == 0);
    TEST_CHECK(cfl_view_entry_at(&view, 2)->key.size == 0);
    TEST_CHECK(cfl_view_get(&view, "", 0, &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_STRING && value.data.as_bytes.size == 0);
    TEST_CHECK(cfl_arena_bytes_used(view.storage) == used);
    TEST_CHECK(cfl_view_remove_at(&view, 2) == 0);

    stored = cfl_view_store(&view, KEY("kept"));
    TEST_CHECK(stored != NULL && memcmp(stored, "kept", 4) == 0);
    TEST_CHECK(cfl_view_store(&view, NULL, 0) != NULL);
    TEST_CHECK(cfl_view_store(&view, NULL, 4) == NULL);

    /* the storage is reused across loads, and the mode is kept */
    cfl_view_reset(&view, NULL, NULL);
    TEST_CHECK(cfl_view_count(&view) == 0);
    memcpy(key, "delta", 5);
    TEST_CHECK(cfl_view_append_int64(&view, key, 5, 3) == 0);
    memset(key, 'x', sizeof(key));
    TEST_CHECK(cfl_view_find(&view, KEY("delta")) == 0);

    cfl_view_destroy(&view);
}

static void variants(void)
{
    struct cfl_view view;
    struct cfl_view_value value;
    struct cfl_array *array;
    struct cfl_array *other;
    struct cfl_kvlist *nested;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *variant;
    struct cfl_variant *fetched;

    cfl_view_init(&view);
    cfl_view_reset(&view, NULL, NULL);

    array = cfl_array_create(2);
    TEST_ASSERT(array != NULL);
    TEST_ASSERT(cfl_array_append_string(array, "a") == 0);
    TEST_ASSERT(cfl_array_append_string(array, "b") == 0);
    TEST_CHECK(cfl_view_append_array(&view, KEY("tags"), array) == 0);

    nested = cfl_kvlist_create();
    TEST_ASSERT(nested != NULL);
    TEST_ASSERT(cfl_kvlist_insert_string(nested, "zone", "a1") == 0);
    TEST_CHECK(cfl_view_append_kvlist(&view, KEY("cloud"), nested) == 0);

    variant = cfl_variant_create_from_string("owned text");
    TEST_ASSERT(variant != NULL);
    TEST_CHECK(cfl_view_append_variant(&view, KEY("text"), variant) == 0);

    /* an object can only have one owner */
    TEST_CHECK(cfl_view_append_variant(&view, KEY("again"), variant) == -1);
    TEST_CHECK(cfl_view_append_array(&view, KEY("again"), array) == -1);
    TEST_CHECK(cfl_view_append_variant(&view, KEY("none"), NULL) == -1);
    TEST_CHECK(cfl_view_append_array(&view, KEY("none"), NULL) == -1);
    TEST_CHECK(cfl_view_append_kvlist(&view, KEY("none"), NULL) == -1);
    TEST_CHECK(cfl_view_count(&view) == 3);

    TEST_CHECK(cfl_view_entry_at(&view, 0)->origin == CFL_VIEW_ENTRY_VARIANT);
    TEST_CHECK(cfl_view_get(&view, KEY("tags"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_ARRAY && value.data.as_variant != NULL &&
               value.data.as_variant->data.as_array == array);
    TEST_CHECK(cfl_view_get(&view, KEY("cloud"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_KVLIST &&
               value.data.as_variant->data.as_kvlist == nested);
    TEST_CHECK(cfl_view_get(&view, KEY("text"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_STRING && ref_is(&value.data.as_bytes, "owned text"));

    /* replacing and removing release the objects the view owns */
    other = cfl_array_create(1);
    TEST_ASSERT(other != NULL);
    TEST_ASSERT(cfl_array_append_int64(other, 1) == 0);
    variant = cfl_variant_create_from_array(other);
    TEST_ASSERT(variant != NULL);
    TEST_CHECK(cfl_view_set_variant_at(&view, 2, variant) == 0);
    TEST_CHECK(cfl_view_set_variant_at(&view, 3, variant) == -1);
    TEST_CHECK(cfl_view_set_variant_at(&view, 0, NULL) == -1);
    TEST_CHECK(cfl_view_set_string_at(&view, 0, KEY("plain")) == 0);
    TEST_CHECK(cfl_view_entry_at(&view, 0)->origin == CFL_VIEW_ENTRY_LITERAL);
    TEST_CHECK(cfl_view_remove_at(&view, 1) == 0);
    TEST_CHECK(cfl_view_count(&view) == 2);

    /* the materialized list is independent of the view */
    kvlist = cfl_view_materialize(&view);
    TEST_ASSERT(kvlist != NULL);
    variant = cfl_view_materialize_at(&view, 1);
    TEST_ASSERT(variant != NULL);
    TEST_CHECK(cfl_view_materialize_at(&view, 2) == NULL);
    cfl_view_destroy(&view);

    TEST_CHECK(cfl_kvlist_count(kvlist) == 2);
    fetched = cfl_kvlist_fetch(kvlist, "tags");
    TEST_CHECK(fetched != NULL && fetched->type == CFL_VARIANT_STRING &&
               strcmp(fetched->data.as_string, "plain") == 0);
    fetched = cfl_kvlist_fetch(kvlist, "text");
    TEST_CHECK(fetched != NULL && fetched->type == CFL_VARIANT_ARRAY &&
               cfl_array_size(fetched->data.as_array) == 1);
    TEST_CHECK(variant->type == CFL_VARIANT_ARRAY &&
               cfl_array_fetch_by_index(variant->data.as_array, 0)->data.as_int64 == 1);

    cfl_variant_destroy(variant);
    cfl_kvlist_destroy(kvlist);
}

static void kvlist_commit_objects(void)
{
    struct cfl_view view;
    struct cfl_array *array;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *variant;
    struct cfl_variant *fetched;
    const char *expected[] = {"tags", "name", "extra", "count"};

    kvlist = cfl_kvlist_create();
    TEST_ASSERT(kvlist != NULL);
    TEST_ASSERT(cfl_kvlist_insert_string(kvlist, "tags", "none") == 0);
    TEST_ASSERT(cfl_kvlist_insert_string(kvlist, "name", "checkout") == 0);

    cfl_view_init(&view);
    cfl_view_copy_set(&view, CFL_TRUE);
    TEST_CHECK(cfl_view_kvlist_load(&view, kvlist) == 0);

    array = cfl_array_create(1);
    TEST_ASSERT(array != NULL);
    TEST_ASSERT(cfl_array_append_string(array, "a") == 0);
    variant = cfl_variant_create_from_array(array);
    TEST_ASSERT(variant != NULL);
    TEST_CHECK(cfl_view_set_variant_at(&view, 0, variant) == 0);

    variant = cfl_variant_create_from_string("more");
    TEST_ASSERT(variant != NULL);
    TEST_CHECK(cfl_view_append_variant(&view, KEY("extra"), variant) == 0);
    TEST_CHECK(cfl_view_append_uint64(&view, KEY("count"), 3) == 0);

    TEST_CHECK(cfl_view_kvlist_commit(&view) == 0);
    check_keys(kvlist, expected, 4);

    /* the objects moved to the list, which now owns them */
    fetched = cfl_kvlist_fetch(kvlist, "tags");
    TEST_CHECK(fetched != NULL && fetched->type == CFL_VARIANT_ARRAY &&
               fetched->data.as_array == array);
    fetched = cfl_kvlist_fetch(kvlist, "extra");
    TEST_CHECK(fetched == variant);
    TEST_CHECK(cfl_view_entry_at(&view, 0)->origin == CFL_VIEW_ENTRY_SOURCE);

    cfl_view_destroy(&view);

    fetched = cfl_kvlist_fetch(kvlist, "count");
    TEST_CHECK(fetched != NULL && fetched->type == CFL_VARIANT_UINT &&
               fetched->data.as_uint64 == 3);
    cfl_kvlist_destroy(kvlist);
}

static void arena_objects(void)
{
    struct cfl_view view;
    struct cfl_arena *arena;
    struct cfl_array *array;
    struct cfl_kvlist *kvlist;
    struct cfl_kvlist *copy;
    struct cfl_variant *variant;
    struct cfl_variant *fetched;

    arena = cfl_arena_create(0);
    TEST_ASSERT(arena != NULL);
    kvlist = sample_kvlist(arena);

    cfl_view_init(&view);
    TEST_CHECK(cfl_view_kvlist_load(&view, kvlist) == 0);

    /* heap objects are copied into the allocator of the list on commit */
    array = cfl_array_create(1);
    TEST_ASSERT(array != NULL);
    TEST_ASSERT(cfl_array_append_string(array, "heap") == 0);
    variant = cfl_variant_create_from_array(array);
    TEST_ASSERT(variant != NULL);
    TEST_CHECK(cfl_view_append_variant(&view, KEY("list"), variant) == 0);
    TEST_CHECK(cfl_view_append_string(&view, KEY("note"), KEY("text")) == 0);
    TEST_CHECK(cfl_view_rename_at(&view, 0, KEY("service")) == 0);
    TEST_CHECK(cfl_view_kvlist_commit(&view) == 0);

    TEST_CHECK(cfl_kvlist_count(kvlist) == 10);
    fetched = cfl_kvlist_fetch(kvlist, "list");
    TEST_CHECK(fetched != NULL && fetched->arena == arena &&
               fetched->type == CFL_VARIANT_ARRAY &&
               cfl_array_size(fetched->data.as_array) == 1);
    TEST_CHECK(cfl_kvlist_fetch(kvlist, "service") != NULL);
    TEST_CHECK(cfl_kvlist_fetch(kvlist, "name") == NULL);

    /* and a view can be materialized into an arena or into the heap */
    copy = cfl_view_materialize_in(&view, arena);
    TEST_ASSERT(copy != NULL);
    TEST_CHECK(copy->arena == arena && cfl_kvlist_count(copy) == 10);
    fetched = cfl_kvlist_fetch(copy, "cloud");
    TEST_CHECK(fetched != NULL && fetched->arena == arena &&
               fetched->type == CFL_VARIANT_KVLIST);

    copy = cfl_view_materialize(&view);
    TEST_ASSERT(copy != NULL);
    TEST_CHECK(copy->arena == NULL && cfl_kvlist_count(copy) == 10);
    fetched = cfl_kvlist_fetch(copy, "tags");
    TEST_CHECK(fetched != NULL && fetched->arena == NULL &&
               cfl_array_size(fetched->data.as_array) == 2);
    cfl_kvlist_destroy(copy);

    cfl_view_destroy(&view);
    cfl_arena_destroy(arena);
}

/*
 * A backend over data that is not made of CFL objects: pairs kept in plain
 * arrays and addressed by index, with one value that only exists as nested
 * data.
 */
struct external {
    const char **keys;
    const char **texts;
    const int64_t *numbers;
    size_t count;
    int value_calls;
    int materialize_calls;
};

static int external_value(struct cfl_view *view, const struct cfl_view_entry *entry,
                          struct cfl_view_value *out)
{
    struct external *external;

    external = view->context;
    external->value_calls++;

    if (external->texts[entry->source.index] != NULL) {
        out->type = CFL_VARIANT_STRING;
        out->data.as_bytes.data = external->texts[entry->source.index];
        out->data.as_bytes.size = strlen(external->texts[entry->source.index]);
    }
    else if (external->numbers[entry->source.index] >= 0) {
        out->type = CFL_VARIANT_INT;
        out->data.as_int64 = external->numbers[entry->source.index];
    }
    else {
        /* a list that has no CFL object behind it */
        out->type = CFL_VARIANT_ARRAY;
    }

    return 0;
}

static struct cfl_variant *external_materialize(struct cfl_view *view,
                                                const struct cfl_view_entry *entry)
{
    struct external *external;
    struct cfl_array *array;
    struct cfl_variant *value;

    external = view->context;
    external->materialize_calls++;

    if (external->texts[entry->source.index] != NULL) {
        return cfl_variant_create_from_string((char *) external->texts[entry->source.index]);
    }
    if (external->numbers[entry->source.index] >= 0) {
        return cfl_variant_create_from_int64(external->numbers[entry->source.index]);
    }

    array = cfl_array_create(2);
    if (array == NULL) {
        return NULL;
    }
    if (cfl_array_append_int64(array, 1) != 0 || cfl_array_append_int64(array, 2) != 0) {
        cfl_array_destroy(array);
        return NULL;
    }
    value = cfl_variant_create_from_array(array);
    if (value == NULL) {
        cfl_array_destroy(array);
    }

    return value;
}

static const struct cfl_view_backend external_backend = {
    "external",
    external_value,
    external_materialize,
};

static const struct cfl_view_backend opaque_backend = {
    "opaque",
    NULL,
    NULL,
};

static int external_load(struct cfl_view *view, const struct cfl_view_backend *backend,
                         struct external *external)
{
    size_t index;

    cfl_view_reset(view, backend, external);
    for (index = 0; index < external->count; index++) {
        if (cfl_view_load_index(view, external->keys[index], strlen(external->keys[index]),
                                (int64_t) index) != 0) {
            return -1;
        }
    }

    return 0;
}

static void custom_backend(void)
{
    size_t round;
    struct cfl_view view;
    struct cfl_view_value value;
    struct external external;
    struct cfl_arena *arena;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *fetched;
    const struct cfl_view_entry *entry;
    const char *keys[] = {"host", "code", "path", "ids"};
    const char *texts[] = {"web-1", NULL, "/cart", NULL};
    const int64_t numbers[] = {0, 503, 0, -1};
    const char *expected[] = {"hostname", "path", "ids", "team"};

    memset(&external, 0, sizeof(external));
    external.keys = keys;
    external.texts = texts;
    external.numbers = numbers;
    external.count = 4;

    cfl_view_init(&view);

    /* the same view serves many loads */
    for (round = 0; round < 3; round++) {
        external.value_calls = 0;
        external.materialize_calls = 0;

        TEST_CHECK(external_load(&view, &external_backend, &external) == 0);
        TEST_CHECK(cfl_view_count(&view) == 4);
        TEST_CHECK(cfl_view_modified(&view) == 0);

        /* loading and looking up keys does not decode any value */
        TEST_CHECK(cfl_view_find(&view, KEY("path")) == 2);
        TEST_CHECK(external.value_calls == 0);

        TEST_CHECK(cfl_view_get(&view, KEY("code"), &value) == 1);
        TEST_CHECK(value.type == CFL_VARIANT_INT && value.data.as_int64 == 503);
        TEST_CHECK(cfl_view_get(&view, KEY("ids"), &value) == 1);
        TEST_CHECK(value.type == CFL_VARIANT_ARRAY && value.data.as_variant == NULL);
        TEST_CHECK(external.value_calls == 2);

        /* edits stay in the entry table: the source is never written */
        TEST_CHECK(cfl_view_rename_at(&view, 0, KEY("hostname")) == 0);
        TEST_CHECK(cfl_view_remove_at(&view, 1) == 0);
        TEST_CHECK(cfl_view_append_string(&view, KEY("team"), KEY("store")) == 0);
        TEST_CHECK(strcmp(keys[0], "host") == 0 && numbers[1] == 503);

        /* what a serializer sees: source entries keep their handle */
        entry = cfl_view_entry_at(&view, 0);
        TEST_CHECK(entry->origin == CFL_VIEW_ENTRY_SOURCE && entry->key_changed &&
                   entry->source.index == 0 && ref_is(&entry->key, "hostname"));
        entry = cfl_view_entry_at(&view, 1);
        TEST_CHECK(entry->origin == CFL_VIEW_ENTRY_SOURCE && !entry->key_changed &&
                   entry->source.index == 2);
        entry = cfl_view_entry_at(&view, 3);
        TEST_CHECK(entry->origin == CFL_VIEW_ENTRY_LITERAL &&
                   ref_is(&entry->value.data.as_bytes, "store"));

        /* this backend has no list to commit to */
        TEST_CHECK(cfl_view_kvlist_commit(&view) == -1);

        kvlist = cfl_view_materialize(&view);
        TEST_ASSERT(kvlist != NULL);
        check_keys(kvlist, expected, 4);
        TEST_CHECK(external.materialize_calls == 3);
        fetched = cfl_kvlist_fetch(kvlist, "hostname");
        TEST_CHECK(fetched != NULL && strcmp(fetched->data.as_string, "web-1") == 0);
        fetched = cfl_kvlist_fetch(kvlist, "ids");
        TEST_CHECK(fetched != NULL && fetched->type == CFL_VARIANT_ARRAY &&
                   cfl_array_size(fetched->data.as_array) == 2);
        cfl_kvlist_destroy(kvlist);

        fetched = cfl_view_materialize_at(&view, 2);
        TEST_CHECK(fetched != NULL && fetched->type == CFL_VARIANT_ARRAY);
        cfl_variant_destroy(fetched);
    }

    /* heap results of a backend are moved into the requested arena */
    arena = cfl_arena_create(0);
    TEST_ASSERT(arena != NULL);
    kvlist = cfl_view_materialize_in(&view, arena);
    TEST_ASSERT(kvlist != NULL);
    fetched = cfl_kvlist_fetch(kvlist, "ids");
    TEST_CHECK(fetched != NULL && fetched->arena == arena &&
               cfl_array_size(fetched->data.as_array) == 2);
    cfl_arena_destroy(arena);

    /* a backend without callbacks still supports keys, edits and literals */
    TEST_CHECK(external_load(&view, &opaque_backend, &external) == 0);
    TEST_CHECK(cfl_view_find(&view, KEY("code")) == 1);
    TEST_CHECK(cfl_view_get(&view, KEY("code"), &value) == -1);
    TEST_CHECK(cfl_view_materialize(&view) == NULL);
    TEST_CHECK(cfl_view_materialize_at(&view, 0) == NULL);
    TEST_CHECK(cfl_view_set_int64_at(&view, 1, 200) == 0);
    TEST_CHECK(cfl_view_get(&view, KEY("code"), &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_INT && value.data.as_int64 == 200);

    cfl_view_destroy(&view);
}

static void growth(void)
{
    size_t index;
    char key[16];
    struct cfl_view view;
    struct cfl_view_value value;

    cfl_view_init(&view);
    cfl_view_copy_set(&view, CFL_TRUE);
    cfl_view_reset(&view, NULL, NULL);

    TEST_CHECK(cfl_view_reserve(&view, SIZE_MAX) == -1);
    TEST_CHECK(cfl_view_reserve(&view, 4) == 0);
    TEST_CHECK(cfl_view_reserve(&view, 2) == 0);

    /* enough pairs to grow the table and to use several storage chunks */
    for (index = 0; index < 2000; index++) {
        snprintf(key, sizeof(key), "key-%04zu", index);
        TEST_ASSERT(cfl_view_append_string(&view, key, 8, key, 8) == 0);
    }
    TEST_CHECK(cfl_view_count(&view) == 2000);

    TEST_CHECK(cfl_view_find(&view, KEY("key-0000")) == 0);
    TEST_CHECK(cfl_view_find(&view, KEY("key-1999")) == 1999);
    TEST_CHECK(cfl_view_get(&view, KEY("key-1024"), &value) == 1);
    TEST_CHECK(ref_is(&value.data.as_bytes, "key-1024"));

    for (index = 0; index < 1999; index++) {
        TEST_ASSERT(cfl_view_remove_at(&view, 0) == 0);
    }
    TEST_CHECK(cfl_view_count(&view) == 1);
    TEST_CHECK(cfl_view_find(&view, KEY("key-1999")) == 0);

    cfl_view_destroy(&view);

    /* destroying a view that was never used is fine */
    cfl_view_init(&view);
    cfl_view_destroy(&view);
}

/* Keys of the list an edit borrows stay readable until the commit is done. */
static void kvlist_commit_borrowed_keys(void)
{
    struct cfl_view view;
    struct cfl_view_ref key_a;
    struct cfl_view_ref key_b;
    struct cfl_view_ref key_c;
    struct cfl_variant *fetched;
    struct cfl_kvlist *kvlist;
    const char *expected[] = {"c", "renamed", "a", "b"};

    kvlist = cfl_kvlist_create();
    TEST_ASSERT(kvlist != NULL);
    TEST_ASSERT(cfl_kvlist_insert_string(kvlist, "a", "1") == 0);
    TEST_ASSERT(cfl_kvlist_insert_string(kvlist, "b", "2") == 0);
    TEST_ASSERT(cfl_kvlist_insert_string(kvlist, "c", "3") == 0);

    cfl_view_init(&view);
    TEST_ASSERT(cfl_view_kvlist_load(&view, kvlist) == 0);
    key_a = cfl_view_entry_at(&view, 0)->key;
    key_b = cfl_view_entry_at(&view, 1)->key;
    key_c = cfl_view_entry_at(&view, 2)->key;

    /* two pairs trade names, and a new pair takes the name of a renamed one */
    TEST_CHECK(cfl_view_rename_at(&view, 0, key_c.data, key_c.size) == 0);
    TEST_CHECK(cfl_view_rename_at(&view, 2, key_a.data, key_a.size) == 0);
    TEST_CHECK(cfl_view_rename_at(&view, 1, KEY("renamed")) == 0);
    TEST_CHECK(cfl_view_append_string(&view, key_b.data, key_b.size, KEY("4")) == 0);

    TEST_CHECK(cfl_view_kvlist_commit(&view) == 0);
    check_keys(kvlist, expected, 4);
    fetched = cfl_kvlist_fetch(kvlist, "c");
    TEST_CHECK(fetched != NULL && strcmp(fetched->data.as_string, "1") == 0);
    fetched = cfl_kvlist_fetch(kvlist, "a");
    TEST_CHECK(fetched != NULL && strcmp(fetched->data.as_string, "3") == 0);
    fetched = cfl_kvlist_fetch(kvlist, "b");
    TEST_CHECK(fetched != NULL && strcmp(fetched->data.as_string, "4") == 0);

    /* the view describes the list as it is now */
    TEST_CHECK(cfl_view_find(&view, KEY("renamed")) == 1);
    TEST_CHECK(cfl_view_modified(&view) == 0);

    cfl_view_destroy(&view);
    cfl_kvlist_destroy(kvlist);
}

/* A released view is detached: its pending edits cannot reach the list. */
static void release_detaches(void)
{
    struct cfl_view view;
    struct cfl_kvlist *kvlist;
    const char *expected[] = {"a", "b"};

    kvlist = cfl_kvlist_create();
    TEST_ASSERT(kvlist != NULL);
    TEST_ASSERT(cfl_kvlist_insert_string(kvlist, "a", "1") == 0);
    TEST_ASSERT(cfl_kvlist_insert_string(kvlist, "b", "2") == 0);

    cfl_view_init(&view);
    TEST_ASSERT(cfl_view_kvlist_load(&view, kvlist) == 0);
    TEST_CHECK(cfl_view_rename_at(&view, 0, KEY("renamed")) == 0);

    cfl_view_release(&view);
    TEST_CHECK(cfl_view_count(&view) == 0);
    TEST_CHECK(cfl_view_modified(&view) == 0);
    TEST_CHECK(cfl_view_kvlist_commit(&view) != 0);
    check_keys(kvlist, expected, 2);

    /* an edit after the release has no list to go to either */
    TEST_CHECK(cfl_view_append_string(&view, KEY("c"), KEY("3")) == 0);
    TEST_CHECK(cfl_view_kvlist_commit(&view) != 0);
    check_keys(kvlist, expected, 2);

    /* the view is reusable */
    TEST_CHECK(cfl_view_kvlist_load(&view, kvlist) == 0);
    TEST_CHECK(cfl_view_count(&view) == 2);
    TEST_CHECK(cfl_view_kvlist_commit(&view) == 0);
    check_keys(kvlist, expected, 2);

    cfl_view_destroy(&view);
    cfl_kvlist_destroy(kvlist);
}

/* A container variant created without its container is copied as it is. */
static void null_containers(void)
{
    struct cfl_view view;
    struct cfl_variant *value;
    struct cfl_variant *copy;
    struct cfl_kvlist *kvlist;

    cfl_view_init(&view);

    value = cfl_variant_create_from_array(NULL);
    TEST_ASSERT(value != NULL);
    TEST_ASSERT(cfl_view_append_variant(&view, KEY("list"), value) == 0);
    value = cfl_variant_create_from_kvlist(NULL);
    TEST_ASSERT(value != NULL);
    TEST_ASSERT(cfl_view_append_variant(&view, KEY("map"), value) == 0);

    copy = cfl_view_materialize_at(&view, 0);
    TEST_CHECK(copy != NULL && copy->type == CFL_VARIANT_ARRAY &&
               copy->data.as_array == NULL);
    cfl_variant_destroy(copy);
    copy = cfl_view_materialize_at(&view, 1);
    TEST_CHECK(copy != NULL && copy->type == CFL_VARIANT_KVLIST &&
               copy->data.as_kvlist == NULL);
    cfl_variant_destroy(copy);

    kvlist = cfl_view_materialize(&view);
    TEST_CHECK(kvlist != NULL && cfl_kvlist_count(kvlist) == 2);
    cfl_kvlist_destroy(kvlist);

    cfl_view_destroy(&view);
}

TEST_LIST = {
    {"kvlist_read", kvlist_read},
    {"find_modes", find_modes},
    {"kvlist_edit_commit", kvlist_edit_commit},
    {"literals", literals},
    {"copy_mode", copy_mode},
    {"variants", variants},
    {"kvlist_commit_objects", kvlist_commit_objects},
    {"kvlist_commit_borrowed_keys", kvlist_commit_borrowed_keys},
    {"release_detaches", release_detaches},
    {"null_containers", null_containers},
    {"arena_objects", arena_objects},
    {"custom_backend", custom_backend},
    {"growth", growth},
    { 0 }
};
