/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _ATTR_CONTAINER_H_
#define _ATTR_CONTAINER_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include "bh_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Attribute type */
enum {
    ATTR_TYPE_BEGIN = 0,
    ATTR_TYPE_BYTE = ATTR_TYPE_BEGIN,
    ATTR_TYPE_INT8 = ATTR_TYPE_BYTE,
    ATTR_TYPE_SHORT,
    ATTR_TYPE_INT16 = ATTR_TYPE_SHORT,
    ATTR_TYPE_INT,
    ATTR_TYPE_INT32 = ATTR_TYPE_INT,
    ATTR_TYPE_INT64,
    ATTR_TYPE_UINT8,
    ATTR_TYPE_UINT16,
    ATTR_TYPE_UINT32,
    ATTR_TYPE_UINT64,
    /**
     * Why ATTR_TYPE_FLOAT = 10?
     * We determine the number of bytes that should be copied through 1<<(type &
     * 3). ATTR_TYPE_BYTE = 0, so the number of bytes is 1 << 0  = 1.
     * ATTR_TYPE_UINT64 = 7, so the number of bytes is 1 << 3 = 8.
     * Since the float type takes up 4 bytes, ATTR_TYPE_FLOAT should be 10.
     * Calculation: (1 << (10&3)) = (1 << 2) = 4
     */
    ATTR_TYPE_FLOAT = 10,
    ATTR_TYPE_DOUBLE,
    ATTR_TYPE_BOOLEAN,
    ATTR_TYPE_STRING,
    ATTR_TYPE_BYTEARRAY,
    ATTR_TYPE_END = ATTR_TYPE_BYTEARRAY
};

#define ATTR_CONT_READONLY_SHIFT 2

typedef struct attr_container {
    /* container flag:
     * bit0, bit1 denote the implemenation algorithm, 00: buffer, 01: link list
     * bit2 denotes the readonly flag: 1 is readonly and attr cannot be set
     */
    char flags[2];
    /**
     * Buffer format
     * for buffer implementation:
     *   buf length (4 bytes)
     *   tag length (2 bytes)
     *   tag
     *   attr num (2bytes)
     *   attr[0..n-1]:
     *     attr key length (2 bytes)
     *     attr type (1byte)
     *     attr value (length depends on attr type)
     */
    char buf[1];
} attr_container_t;

/**
 * Create attribute container
 *
 * @param tag tag of current attribute container
 *
 * @return the created attribute container, NULL if failed
 */
attr_container_t *
attr_container_create(const char *tag);

/**
 * Destroy attribute container
 *
 * @param attr_cont the attribute container to destroy
 */
void
attr_container_destroy(const attr_container_t *attr_cont);

/**
 * Set short attribute in attribute container
 *
 * @param p_attr_cont pointer to attribute container to set attribute, and
 * return the new attribute container if it is re-created
 * @param key the attribute key
 * @param value the attribute value
 *
 * @return true if success, false otherwise
 */
bool
attr_container_set_short(attr_container_t **p_attr_cont, const char *key,
                         short value);

/**
 * Set int16 attribute in attribute container
 *
 * @param p_attr_cont pointer to attribute container to set attribute, and
 * return the new attribute container if it is re-created
 * @param key the attribute key
 * @param value the attribute value
 *
 * @return true if success, false otherwise
 */
bool
attr_container_set_int16(attr_container_t **p_attr_cont, const char *key,
                         int16_t value);

/**
 * Set int attribute in attribute container
 *
 * @param p_attr_cont pointer to attribute container to set attribute, and
 * return the new attribute container if it is re-created
 * @param key the attribute key
 * @param value the attribute value
 *
 * @return true if success, false otherwise
 */
bool
attr_container_set_int(attr_container_t **p_attr_cont, const char *key,
                       int value);

/**
 * Set int32 attribute in attribute container
 *
 * @param p_attr_cont pointer to attribute container to set attribute, and
 * return the new attribute container if it is re-created
 * @param key the attribute key
 * @param value the attribute value
 *
 * @return true if success, false otherwise
 */
bool
attr_container_set_int32(attr_container_t **p_attr_cont, const char *key,
                         int32_t value);

/**
 * Set uint32 attribute in attribute container
 *
 * @param p_attr_cont pointer to attribute container to set attribute, and
 * return the new attribute container if it is re-created
 * @param key the attribute key
 * @param value the attribute value
 *
 * @return true if success, false otherwise
 */
bool
attr_container_set_uint32(attr_container_t **p_attr_cont, const char *key,
                          uint32_t value);

/**
 * Set int64 attribute in attribute container
 *
 * @param p_attr_cont pointer to attribute container to set attribute, and
 * return the new attribute container if it is re-created
 * @param key the attribute key
 * @param value the attribute value
 *
 * @return true if success, false otherwise
 */
bool
attr_container_set_int64(attr_container_t **p_attr_cont, const char *key,
                         int64_t value);

/**
 * Set uint64 attribute in attribute container
 *
 * @param p_attr_cont pointer to attribute container to set attribute, and
 * return the new attribute container if it is re-created
 * @param key the attribute key
 * @param value the attribute value
 *
 * @return true if success, false otherwise
 */
bool
attr_container_set_uint64(attr_container_t **p_attr_cont, const char *key,
                          uint64_t value);

/**
 * Set byte attribute in attribute container
 *
 * @param p_attr_cont pointer to attribute container to set attribute, and
 * return the new attribute container if it is re-created
 * @param key the attribute key
 * @param value the attribute value
 *
 * @return true if success, false otherwise
 */
bool
attr_container_set_byte(attr_container_t **p_attr_cont, const char *key,
                        int8_t value);

/**
 * Set int8 attribute in attribute container
 *
 * @param p_attr_cont pointer to attribute container to set attribute, and
 * return the new attribute container if it is re-created
 * @param key the attribute key
 * @param value the attribute value
 *
 * @return true if success, false otherwise
 */
bool
attr_container_set_int8(attr_container_t **p_attr_cont, const char *key,
                        int8_t value);

/**
 * Set uint8 attribute in attribute container
 *
 * @param p_attr_cont pointer to attribute container to set attribute, and
 * return the new attribute container if it is re-created
 * @param key the attribute key
 * @param value the attribute value
 *
 * @return true if success, false otherwise
 */
bool
attr_container_set_uint8(attr_container_t **p_attr_cont, const char *key,
                         uint8_t value);

/**
 * Set uint16 attribute in attribute container
 *
 * @param p_attr_cont pointer to attribute container to set attribute, and
 * return the new attribute container if it is re-created
 * @param key the attribute key
 * @param value the attribute value
 *
 * @return true if success, false otherwise
 */
bool
attr_container_set_uint16(attr_container_t **p_attr_cont, const char *key,
                          uint16_t value);

/**
 * Set float attribute in attribute container
 *
 * @param p_attr_cont pointer to attribute container to set attribute, and
 * return the new attribute container if it is re-created
 * @param key the attribute key
 * @param value the attribute value
 *
 * @return true if success, false otherwise
 */
bool
attr_container_set_float(attr_container_t **p_attr_cont, const char *key,
                         float value);

/**
 * Set double attribute in attribute container
 *
 * @param p_attr_cont pointer to attribute container to set attribute, and
 * return the new attribute container if it is re-created
 * @param key the attribute key
 * @param value the attribute value
 *
 * @return true if success, false otherwise
 */
bool
attr_container_set_double(attr_container_t **p_attr_cont, const char *key,
                          double value);

/**
 * Set bool attribute in attribute container
 *
 * @param p_attr_cont pointer to attribute container to set attribute, and
 * return the new attribute container if it is re-created
 * @param key the attribute key
 * @param value the attribute value
 *
 * @return true if success, false otherwise
 */
bool
attr_container_set_bool(attr_container_t **p_attr_cont, const char *key,
                        bool value);

/**
 * Set string attribute in attribute container
 *
 * @param p_attr_cont pointer to attribute container to set attribute, and
 * return the new attribute container if it is re-created
 * @param key the attribute key
 * @param value the attribute value
 *
 * @return true if success, false otherwise
 */
bool
attr_container_set_string(attr_container_t **p_attr_cont, const char *key,
                          const char *value);

/**
 * Set bytearray attribute in attribute container
 *
 * @param p_attr_cont pointer to attribute container to set attribute, and
 * return the new attribute container if it is re-created
 * @param key the attribute key
 * @param value the bytearray buffer
 * @param length the bytearray length
 *
 * @return true if success, false otherwise
 */
bool
attr_container_set_bytearray(attr_container_t **p_attr_cont, const char *key,
                             const int8_t *value, unsigned length);

/**
 * Get tag of current attribute container
 *
 * @param attr_cont the attribute container
 *
 * @return tag of current attribute container
 */
const char *
attr_container_get_tag(const attr_container_t *attr_cont);

/**
 * Get attribute number of current attribute container
 *
 * @param attr_cont the attribute container
 *
 * @return attribute number of current attribute container
 */
uint16_t
attr_container_get_attr_num(const attr_container_t *attr_cont);

/**
 * Whether the attribute container contains an attribute key.
 *
 * @param attr_cont the attribute container
 * @param key the attribute key
 *
 * @return true if key is contained in message, false otherwise
 */
bool
attr_container_contain_key(const attr_container_t *attr_cont, const char *key);

/**
 * Get attribute from attribute container and return it as short value,
 * return 0 if attribute isn't found in message.
 *
 * @param attr_cont the attribute container
 * @param key the attribute key
 *
 * @return the short value of the attribute, 0 if key isn't found
 */
short
attr_container_get_as_short(const attr_container_t *attr_cont, const char *key);

/**
 * Get attribute from attribute container and return it as int16 value,
 * return 0 if attribute isn't found in message.
 *
 * @param attr_cont the attribute container
 * @param key the attribute key
 *
 * @return the short value of the attribute, 0 if key isn't found
 */
int16_t
attr_container_get_as_int16(const attr_container_t *attr_cont, const char *key);

/**
 * Get attribute from attribute container and return it as int value,
 * return 0 if attribute isn't found in message.
 *
 * @param attr_cont the attribute container
 * @param key the attribute key
 *
 * @return the int value of the attribute, 0 if key isn't found
 */
int
attr_container_get_as_int(const attr_container_t *attr_cont, const char *key);

/**
 * Get attribute from attribute container and return it as int32 value,
 * return 0 if attribute isn't found in message.
 *
 * @param attr_cont the attribute container
 * @param key the attribute key
 *
 * @return the int value of the attribute, 0 if key isn't found
 */
int32_t
attr_container_get_as_int32(const attr_container_t *attr_cont, const char *key);

/**
 * Get attribute from attribute container and return it as uint32 value,
 * return 0 if attribute isn't found in message.
 *
 * @param attr_cont the attribute container
 * @param key the attribute key
 *
 * @return the unsigned int value of the attribute, 0 if key isn't found
 */
uint32_t
attr_container_get_as_uint32(const attr_container_t *attr_cont,
                             const char *key);

/**
 * Get attribute from attribute container and return it as int64 value,
 * return 0 if attribute isn't found in attribute container.
 *
 * @param attr_cont the attribute container
 * @param key the attribute key
 *
 * @return the long value of the attribute, 0 if key isn't found
 */
int64_t
attr_container_get_as_int64(const attr_container_t *attr_cont, const char *key);

/**
 * Get attribute from attribute container and return it as uint64 value,
 * return 0 if attribute isn't found in attribute container.
 *
 * @param attr_cont the attribute container
 * @param key the attribute key
 *
 * @return the unsigned long value of the attribute, 0 if key isn't found
 */
uint64_t
attr_container_get_as_uint64(const attr_container_t *attr_cont,
                             const char *key);

/**
 * Get attribute from attribute container and return it as byte value,
 * return 0 if attribute isn't found in attribute container.
 *
 * @param attr_cont the attribute container
 * @param key the attribute key
 *
 * @return the byte value of the attribute, 0 if key isn't found
 */
int8_t
attr_container_get_as_byte(const attr_container_t *attr_cont, const char *key);

/**
 * Get attribute from attribute container and return it as int8 value,
 * return 0 if attribute isn't found in attribute container.
 *
 * @param attr_cont the attribute container
 * @param key the attribute key
 *
 * @return the byte value of the attribute, 0 if key isn't found
 */
int8_t
attr_container_get_as_int8(const attr_container_t *attr_cont, const char *key);

/**
 * Get attribute from attribute container and return it as uint8 value,
 * return 0 if attribute isn't found in attribute container.
 *
 * @param attr_cont the attribute container
 * @param key the attribute key
 *
 * @return the uint8 value of the attribute, 0 if key isn't found
 */
uint8_t
attr_container_get_as_uint8(const attr_container_t *attr_cont, const char *key);

/**
 * Get attribute from attribute container and return it as uint16 value,
 * return 0 if attribute isn't found in attribute container.
 *
 * @param attr_cont the attribute container
 * @param key the attribute key
 *
 * @return the char value of the attribute, 0 if key isn't found
 */
uint16_t
attr_container_get_as_uint16(const attr_container_t *attr_cont,
                             const char *key);

/**
 * Get attribute from attribute container and return it as float value,
 * return 0 if attribute isn't found in attribute container.
 *
 * @param attr_cont the attribute container
 * @param key the attribute key
 *
 * @return the float value of the attribute, 0 if key isn't found
 */
float
attr_container_get_as_float(const attr_container_t *attr_cont, const char *key);

/**
 * Get attribute from attribute container and return it as double value,
 * return 0 if attribute isn't found in attribute container.
 *
 * @param attr_cont the attribute container
 * @param key the attribute key
 *
 * @return the double value of the attribute, 0 if key isn't found
 */
double
attr_container_get_as_double(const attr_container_t *attr_cont,
                             const char *key);

/**
 * Get attribute from attribute container and return it as bool value,
 * return false if attribute isn't found in attribute container.
 *
 * @param attr_cont the attribute container
 * @param key the attribute key
 *
 * @return the bool value of the attribute, 0 if key isn't found
 */
bool
attr_container_get_as_bool(const attr_container_t *attr_cont, const char *key);

/**
 * Get attribute from attribute container and return it as string value,
 * return NULL if attribute isn't found in attribute container.
 *
 * @param attr_cont the attribute container
 * @param key the attribute key
 *
 * @return the string value of the attribute, NULL if key isn't found
 */
char *
attr_container_get_as_string(const attr_container_t *attr_cont,
                             const char *key);

/**
 * Get attribute from attribute container and return it as bytearray value,
 * return 0 if attribute isn't found in attribute container.
 *
 * @param attr_cont the attribute container
 * @param key the attribute key
 *
 * @return the bytearray value of the attribute, NULL if key isn't found
 */
const int8_t *
attr_container_get_as_bytearray(const attr_container_t *attr_cont,
                                const char *key, unsigned *array_length);

/**
 * Get the buffer size of attribute container
 *
 * @param attr_cont the attribute container
 *
 * @return the buffer size of attribute container
 */
unsigned
attr_container_get_serialize_length(const attr_container_t *attr_cont);

/**
 * Serialize attribute container to a buffer
 *
 * @param buf the buffer to receive the serialized data
 * @param attr_cont the attribute container to be serialized
 *
 * @return true if success, false otherwise
 */
bool
attr_container_serialize(char *buf, const attr_container_t *attr_cont);

/**
 * Whether the attribute container is const, or set attribute isn't supported
 *
 * @param attr_cont the attribute container
 *
 * @return true if const, false otherwise
 */
bool
attr_container_is_constant(const attr_container_t *attr_cont);

void
attr_container_dump(const attr_container_t *attr_cont);

#ifndef attr_container_malloc
#define attr_container_malloc WA_MALLOC
#endif

#ifndef attr_container_free
#define attr_container_free WA_FREE
#endif

#ifndef attr_container_printf
#define attr_container_printf printf
#endif

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _ATTR_CONTAINER_H_ */
