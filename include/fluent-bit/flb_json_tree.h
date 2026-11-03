/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#ifndef FLB_JSON_TREE_H
#define FLB_JSON_TREE_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_compat.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef FLB_HAVE_YYJSON
#include <yyjson.h>
#endif

/*
 * Read-only JSON tree for traversal in hot paths. A tree is parsed once and its
 * strings are borrowed from it, no value is copied or converted. Invalid
 * Unicode is replaced like flb_pack_json() does. flb_json_tree_read() returns
 * NULL when the input is not a single JSON value or when no tree backend is
 * built (FLB_YYJSON=Off), callers must keep another way to read the input.
 *
 * The accessors are inline so traversal costs the same as using the backend
 * directly. They accept NULL and nodes of any type: type checks are false,
 * sizes and numbers are zero and strings are NULL.
 */
struct flb_json_tree;
struct flb_json_node;

enum flb_json_node_type {
    FLB_JSON_NODE_NONE = 0,
    FLB_JSON_NODE_NULL,
    FLB_JSON_NODE_BOOL,
    FLB_JSON_NODE_UINT,
    FLB_JSON_NODE_SINT,
    FLB_JSON_NODE_REAL,
    FLB_JSON_NODE_STR,
    FLB_JSON_NODE_ARR,
    FLB_JSON_NODE_OBJ
};

struct flb_json_tree *flb_json_tree_read(const char *input, size_t length);
void flb_json_tree_destroy(struct flb_json_tree *tree);

#ifdef FLB_HAVE_YYJSON

static inline yyjson_val *flb_json_node_val(struct flb_json_node *node)
{
    return (yyjson_val *) node;
}

static inline struct flb_json_node *flb_json_node_wrap(yyjson_val *value)
{
    return (struct flb_json_node *) value;
}

static inline struct flb_json_node *flb_json_tree_root(struct flb_json_tree *tree)
{
    return flb_json_node_wrap(yyjson_doc_get_root((yyjson_doc *) tree));
}

/* one of enum flb_json_node_type, FLB_JSON_NODE_NONE for NULL */
static inline int flb_json_node_type(struct flb_json_node *node)
{
    yyjson_val *value;

    value = flb_json_node_val(node);
    switch (yyjson_get_type(value)) {
    case YYJSON_TYPE_NULL:
        return FLB_JSON_NODE_NULL;
    case YYJSON_TYPE_BOOL:
        return FLB_JSON_NODE_BOOL;
    case YYJSON_TYPE_NUM:
        switch (yyjson_get_subtype(value)) {
        case YYJSON_SUBTYPE_UINT:
            return FLB_JSON_NODE_UINT;
        case YYJSON_SUBTYPE_SINT:
            return FLB_JSON_NODE_SINT;
        default:
            return FLB_JSON_NODE_REAL;
        }
    case YYJSON_TYPE_STR:
        return FLB_JSON_NODE_STR;
    case YYJSON_TYPE_ARR:
        return FLB_JSON_NODE_ARR;
    case YYJSON_TYPE_OBJ:
        return FLB_JSON_NODE_OBJ;
    default:
        return FLB_JSON_NODE_NONE;
    }
}

static inline int flb_json_node_is_null(struct flb_json_node *node)
{
    return yyjson_is_null(flb_json_node_val(node));
}

static inline int flb_json_node_is_bool(struct flb_json_node *node)
{
    return yyjson_is_bool(flb_json_node_val(node));
}

static inline int flb_json_node_is_uint(struct flb_json_node *node)
{
    return yyjson_is_uint(flb_json_node_val(node));
}

static inline int flb_json_node_is_sint(struct flb_json_node *node)
{
    return yyjson_is_sint(flb_json_node_val(node));
}

static inline int flb_json_node_is_int(struct flb_json_node *node)
{
    return yyjson_is_int(flb_json_node_val(node));
}

static inline int flb_json_node_is_real(struct flb_json_node *node)
{
    return yyjson_is_real(flb_json_node_val(node));
}

static inline int flb_json_node_is_str(struct flb_json_node *node)
{
    return yyjson_is_str(flb_json_node_val(node));
}

static inline int flb_json_node_is_arr(struct flb_json_node *node)
{
    return yyjson_is_arr(flb_json_node_val(node));
}

static inline int flb_json_node_is_obj(struct flb_json_node *node)
{
    return yyjson_is_obj(flb_json_node_val(node));
}

static inline int flb_json_node_get_bool(struct flb_json_node *node)
{
    return yyjson_get_bool(flb_json_node_val(node));
}

static inline uint64_t flb_json_node_get_uint(struct flb_json_node *node)
{
    return yyjson_get_uint(flb_json_node_val(node));
}

static inline int64_t flb_json_node_get_sint(struct flb_json_node *node)
{
    return yyjson_get_sint(flb_json_node_val(node));
}

static inline double flb_json_node_get_real(struct flb_json_node *node)
{
    return yyjson_get_real(flb_json_node_val(node));
}

static inline const char *flb_json_node_get_str(struct flb_json_node *node)
{
    return yyjson_get_str(flb_json_node_val(node));
}

static inline size_t flb_json_node_get_len(struct flb_json_node *node)
{
    return yyjson_get_len(flb_json_node_val(node));
}

/* string and its length, or NULL and a zero length when node is not a string */
static inline const char *flb_json_node_get_strn(struct flb_json_node *node,
                                                 size_t *length)
{
    yyjson_val *value;

    value = flb_json_node_val(node);
    if (!yyjson_is_str(value)) {
        *length = 0;
        return NULL;
    }

    *length = unsafe_yyjson_get_len(value);
    return unsafe_yyjson_get_str(value);
}

static inline size_t flb_json_node_arr_size(struct flb_json_node *node)
{
    return yyjson_arr_size(flb_json_node_val(node));
}

static inline size_t flb_json_node_obj_size(struct flb_json_node *node)
{
    return yyjson_obj_size(flb_json_node_val(node));
}

/* first element of an array, or first key of an object */
static inline struct flb_json_node *flb_json_node_first(struct flb_json_node *node)
{
    yyjson_val *value;

    value = flb_json_node_val(node);
    if ((!yyjson_is_arr(value) && !yyjson_is_obj(value)) ||
        unsafe_yyjson_get_len(value) == 0) {
        return NULL;
    }

    return flb_json_node_wrap(unsafe_yyjson_get_first(value));
}

/* element or key that follows the given element or object value */
static inline struct flb_json_node *flb_json_node_next(struct flb_json_node *node)
{
    if (node == NULL) {
        return NULL;
    }

    /* callers stop on the container size, the last element has no successor */
    return flb_json_node_wrap(unsafe_yyjson_get_next(flb_json_node_val(node)));
}

/* value of an object key */
static inline struct flb_json_node *flb_json_node_key_value(struct flb_json_node *key)
{
    if (key == NULL) {
        return NULL;
    }

    /* in a yyjson tree each object value follows its key */
    return flb_json_node_wrap(flb_json_node_val(key) + 1);
}

/* value of the first key that matches name ignoring ASCII case, or NULL */
static inline struct flb_json_node *flb_json_node_obj_get_case(struct flb_json_node *object,
                                                               const char *name,
                                                               size_t length)
{
    size_t index;
    size_t maximum;
    yyjson_val *key;
    yyjson_val *value;

    if (name == NULL || !yyjson_is_obj(flb_json_node_val(object))) {
        return NULL;
    }

    yyjson_obj_foreach(flb_json_node_val(object), index, maximum, key, value) {
        if (unsafe_yyjson_get_len(key) == length &&
            strncasecmp(unsafe_yyjson_get_str(key), name, length) == 0) {
            return flb_json_node_wrap(value);
        }
    }

    return NULL;
}

#else

/* without a tree backend no tree is read, so no node exists */
static inline struct flb_json_node *flb_json_tree_root(struct flb_json_tree *tree)
{
    (void) tree;
    return NULL;
}

static inline int flb_json_node_type(struct flb_json_node *node)
{
    (void) node;
    return FLB_JSON_NODE_NONE;
}

static inline int flb_json_node_is_null(struct flb_json_node *node)
{
    (void) node;
    return 0;
}

static inline int flb_json_node_is_bool(struct flb_json_node *node)
{
    (void) node;
    return 0;
}

static inline int flb_json_node_is_uint(struct flb_json_node *node)
{
    (void) node;
    return 0;
}

static inline int flb_json_node_is_sint(struct flb_json_node *node)
{
    (void) node;
    return 0;
}

static inline int flb_json_node_is_int(struct flb_json_node *node)
{
    (void) node;
    return 0;
}

static inline int flb_json_node_is_real(struct flb_json_node *node)
{
    (void) node;
    return 0;
}

static inline int flb_json_node_is_str(struct flb_json_node *node)
{
    (void) node;
    return 0;
}

static inline int flb_json_node_is_arr(struct flb_json_node *node)
{
    (void) node;
    return 0;
}

static inline int flb_json_node_is_obj(struct flb_json_node *node)
{
    (void) node;
    return 0;
}

static inline int flb_json_node_get_bool(struct flb_json_node *node)
{
    (void) node;
    return 0;
}

static inline uint64_t flb_json_node_get_uint(struct flb_json_node *node)
{
    (void) node;
    return 0;
}

static inline int64_t flb_json_node_get_sint(struct flb_json_node *node)
{
    (void) node;
    return 0;
}

static inline double flb_json_node_get_real(struct flb_json_node *node)
{
    (void) node;
    return 0;
}

static inline const char *flb_json_node_get_str(struct flb_json_node *node)
{
    (void) node;
    return NULL;
}

static inline size_t flb_json_node_get_len(struct flb_json_node *node)
{
    (void) node;
    return 0;
}

static inline const char *flb_json_node_get_strn(struct flb_json_node *node,
                                                 size_t *length)
{
    (void) node;
    *length = 0;
    return NULL;
}

static inline size_t flb_json_node_arr_size(struct flb_json_node *node)
{
    (void) node;
    return 0;
}

static inline size_t flb_json_node_obj_size(struct flb_json_node *node)
{
    (void) node;
    return 0;
}

static inline struct flb_json_node *flb_json_node_first(struct flb_json_node *node)
{
    (void) node;
    return NULL;
}

static inline struct flb_json_node *flb_json_node_next(struct flb_json_node *node)
{
    (void) node;
    return NULL;
}

static inline struct flb_json_node *flb_json_node_key_value(struct flb_json_node *key)
{
    (void) key;
    return NULL;
}

static inline struct flb_json_node *flb_json_node_obj_get_case(struct flb_json_node *object,
                                                               const char *name,
                                                               size_t length)
{
    (void) object;
    (void) name;
    (void) length;
    return NULL;
}

#endif

#define flb_json_node_arr_foreach(array, index, maximum, value)              \
    for ((index) = 0, (maximum) = flb_json_node_arr_size(array),            \
         (value) = flb_json_node_first(array);                              \
         (index) < (maximum);                                               \
         (index)++, (value) = flb_json_node_next(value))

#define flb_json_node_obj_foreach(object, index, maximum, key, value)       \
    for ((index) = 0, (maximum) = flb_json_node_obj_size(object),           \
         (key) = flb_json_node_first(object),                               \
         (value) = flb_json_node_key_value(key);                            \
         (index) < (maximum);                                               \
         (index)++, (key) = flb_json_node_next(value),                      \
         (value) = flb_json_node_key_value(key))

#endif
