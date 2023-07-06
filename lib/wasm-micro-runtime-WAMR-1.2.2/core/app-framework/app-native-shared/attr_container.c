/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bi-inc/attr_container.h"

typedef union jvalue {
    bool z;
    int8_t i8;
    uint8_t u8;
    int16_t i16;
    uint16_t u16;
    int32_t i32;
    uint32_t u32;
    int64_t i64;
    uint64_t u64;
    float f;
    double d;
} jvalue;

static inline int16_t
get_int16(const char *buf)
{
    int16_t ret;
    bh_memcpy_s(&ret, sizeof(int16_t), buf, sizeof(int16_t));
    return ret;
}

static inline uint16_t
get_uint16(const char *buf)
{
    uint16_t ret;
    bh_memcpy_s(&ret, sizeof(uint16_t), buf, sizeof(uint16_t));
    return ret;
}

static inline int32_t
get_int32(const char *buf)
{
    int32_t ret;
    bh_memcpy_s(&ret, sizeof(int32_t), buf, sizeof(int32_t));
    return ret;
}

static inline uint32_t
get_uint32(const char *buf)
{
    uint32_t ret;
    bh_memcpy_s(&ret, sizeof(uint32_t), buf, sizeof(uint32_t));
    return ret;
}

static inline int64_t
get_int64(const char *buf)
{
    int64_t ret;
    bh_memcpy_s(&ret, sizeof(int64_t), buf, sizeof(int64_t));
    return ret;
}

static inline uint64_t
get_uint64(const char *buf)
{
    uint64_t ret;
    bh_memcpy_s(&ret, sizeof(uint64_t), buf, sizeof(uint64_t));
    return ret;
}

static inline void
set_int16(char *buf, int16_t v)
{
    bh_memcpy_s(buf, sizeof(int16_t), &v, sizeof(int16_t));
}

static inline void
set_uint16(char *buf, uint16_t v)
{
    bh_memcpy_s(buf, sizeof(uint16_t), &v, sizeof(uint16_t));
}

static inline void
set_int32(char *buf, int32_t v)
{
    bh_memcpy_s(buf, sizeof(int32_t), &v, sizeof(int32_t));
}

static inline void
set_uint32(char *buf, uint32_t v)
{
    bh_memcpy_s(buf, sizeof(uint32_t), &v, sizeof(uint32_t));
}

static inline void
set_int64(char *buf, int64_t v)
{
    bh_memcpy_s(buf, sizeof(int64_t), &v, sizeof(int64_t));
}

static inline void
set_uint64(char *buf, uint64_t v)
{
    bh_memcpy_s(buf, sizeof(uint64_t), &v, sizeof(uint64_t));
}

char *
attr_container_get_attr_begin(const attr_container_t *attr_cont,
                              uint32_t *p_total_length, uint16_t *p_attr_num)
{
    char *p = (char *)attr_cont->buf;
    uint16_t str_len, attr_num;
    uint32_t total_length;

    /* skip total length */
    total_length = get_uint32(p);
    p += sizeof(uint32_t);
    if (!total_length)
        return NULL;

    /* tag length */
    str_len = get_uint16(p);
    p += sizeof(uint16_t);
    if (!str_len)
        return NULL;

    /* tag content */
    p += str_len;
    if ((uint32_t)(p - attr_cont->buf) >= total_length)
        return NULL;

    /* attribute num */
    attr_num = get_uint16(p);
    p += sizeof(uint16_t);
    if ((uint32_t)(p - attr_cont->buf) >= total_length)
        return NULL;

    if (p_total_length)
        *p_total_length = total_length;

    if (p_attr_num)
        *p_attr_num = attr_num;

    /* first attribute */
    return p;
}

static char *
attr_container_get_attr_next(const char *curr_attr)
{
    char *p = (char *)curr_attr;
    uint8_t type;

    /* key length and key */
    p += sizeof(uint16_t) + get_uint16(p);
    type = *p++;

    /* Byte type to Boolean type */
    if (type >= ATTR_TYPE_BYTE && type <= ATTR_TYPE_BOOLEAN) {
        p += 1 << (type & 3);
        return p;
    }
    /* String type */
    else if (type == ATTR_TYPE_STRING) {
        p += sizeof(uint16_t) + get_uint16(p);
        return p;
    }
    /* ByteArray type */
    else if (type == ATTR_TYPE_BYTEARRAY) {
        p += sizeof(uint32_t) + get_uint32(p);
        return p;
    }

    return NULL;
}

static const char *
attr_container_find_attr(const attr_container_t *attr_cont, const char *key)
{
    uint32_t total_length;
    uint16_t str_len, attr_num, i;
    const char *p = attr_cont->buf;

    if (!key)
        return NULL;

    if (!(p = attr_container_get_attr_begin(attr_cont, &total_length,
                                            &attr_num)))
        return NULL;

    for (i = 0; i < attr_num; i++) {
        /* key length */
        if (!(str_len = get_uint16(p)))
            return NULL;

        if (str_len == strlen(key) + 1
            && memcmp(p + sizeof(uint16_t), key, str_len) == 0) {
            if ((uint32_t)(p + sizeof(uint16_t) + str_len - attr_cont->buf)
                >= total_length)
                return NULL;
            return p;
        }

        if (!(p = attr_container_get_attr_next(p)))
            return NULL;
    }

    return NULL;
}

char *
attr_container_get_attr_end(const attr_container_t *attr_cont)
{
    uint32_t total_length;
    uint16_t attr_num, i;
    char *p;

    if (!(p = attr_container_get_attr_begin(attr_cont, &total_length,
                                            &attr_num)))
        return NULL;

    for (i = 0; i < attr_num; i++)
        if (!(p = attr_container_get_attr_next(p)))
            return NULL;

    return p;
}

static char *
attr_container_get_msg_end(attr_container_t *attr_cont)
{
    char *p = attr_cont->buf;
    return p + get_uint32(p);
}

uint16_t
attr_container_get_attr_num(const attr_container_t *attr_cont)
{
    uint16_t str_len;
    /* skip total length */
    const char *p = attr_cont->buf + sizeof(uint32_t);

    str_len = get_uint16(p);
    /* skip tag length and tag */
    p += sizeof(uint16_t) + str_len;

    /* attribute num */
    return get_uint16(p);
}

static void
attr_container_inc_attr_num(attr_container_t *attr_cont)
{
    uint16_t str_len, attr_num;
    /* skip total length */
    char *p = attr_cont->buf + sizeof(uint32_t);

    str_len = get_uint16(p);
    /* skip tag length and tag */
    p += sizeof(uint16_t) + str_len;

    /* attribute num */
    attr_num = get_uint16(p) + 1;
    set_uint16(p, attr_num);
}

attr_container_t *
attr_container_create(const char *tag)
{
    attr_container_t *attr_cont;
    int length, tag_length;
    char *p;

    tag_length = tag ? strlen(tag) + 1 : 1;
    length = offsetof(attr_container_t, buf) +
             /* total length + tag length + tag + reserved 100 bytes */
             sizeof(uint32_t) + sizeof(uint16_t) + tag_length + 100;

    if (!(attr_cont = attr_container_malloc(length))) {
        attr_container_printf(
            "Create attr_container failed: allocate memory failed.\r\n");
        return NULL;
    }

    memset(attr_cont, 0, length);
    p = attr_cont->buf;

    /* total length */
    set_uint32(p, length - offsetof(attr_container_t, buf));
    p += 4;

    /* tag length, tag */
    set_uint16(p, tag_length);
    p += 2;
    if (tag)
        bh_memcpy_s(p, tag_length, tag, tag_length);

    return attr_cont;
}

void
attr_container_destroy(const attr_container_t *attr_cont)
{
    if (attr_cont)
        attr_container_free((char *)attr_cont);
}

static bool
check_set_attr(attr_container_t **p_attr_cont, const char *key)
{
    uint32_t flags;

    if (!p_attr_cont || !*p_attr_cont || !key || strlen(key) == 0) {
        attr_container_printf(
            "Set attribute failed: invalid input arguments.\r\n");
        return false;
    }

    flags = get_uint32((char *)*p_attr_cont);
    if (flags & ATTR_CONT_READONLY_SHIFT) {
        attr_container_printf(
            "Set attribute failed: attribute container is readonly.\r\n");
        return false;
    }

    return true;
}

bool
attr_container_set_attr(attr_container_t **p_attr_cont, const char *key,
                        int type, const void *value, int value_length)
{
    attr_container_t *attr_cont, *attr_cont1;
    uint16_t str_len;
    uint32_t total_length, attr_len;
    char *p, *p1, *attr_end, *msg_end, *attr_buf;

    if (!check_set_attr(p_attr_cont, key)) {
        return false;
    }

    attr_cont = *p_attr_cont;
    p = attr_cont->buf;
    total_length = get_uint32(p);

    if (!(attr_end = attr_container_get_attr_end(attr_cont))) {
        attr_container_printf("Set attr failed: get attr end failed.\r\n");
        return false;
    }

    msg_end = attr_container_get_msg_end(attr_cont);

    /* key len + key + '\0' + type */
    attr_len = sizeof(uint16_t) + strlen(key) + 1 + 1;
    if (type >= ATTR_TYPE_BYTE && type <= ATTR_TYPE_BOOLEAN)
        attr_len += 1 << (type & 3);
    else if (type == ATTR_TYPE_STRING)
        attr_len += sizeof(uint16_t) + value_length;
    else if (type == ATTR_TYPE_BYTEARRAY)
        attr_len += sizeof(uint32_t) + value_length;

    if (!(p = attr_buf = attr_container_malloc(attr_len))) {
        attr_container_printf("Set attr failed: allocate memory failed.\r\n");
        return false;
    }

    /* Set the attr buf */
    str_len = (uint16_t)(strlen(key) + 1);
    set_uint16(p, str_len);
    p += sizeof(uint16_t);
    bh_memcpy_s(p, str_len, key, str_len);
    p += str_len;

    *p++ = type;
    if (type >= ATTR_TYPE_BYTE && type <= ATTR_TYPE_BOOLEAN)
        bh_memcpy_s(p, 1 << (type & 3), value, 1 << (type & 3));
    else if (type == ATTR_TYPE_STRING) {
        set_uint16(p, value_length);
        p += sizeof(uint16_t);
        bh_memcpy_s(p, value_length, value, value_length);
    }
    else if (type == ATTR_TYPE_BYTEARRAY) {
        set_uint32(p, value_length);
        p += sizeof(uint32_t);
        bh_memcpy_s(p, value_length, value, value_length);
    }

    if ((p = (char *)attr_container_find_attr(attr_cont, key))) {
        /* key found */
        p1 = attr_container_get_attr_next(p);

        if (p1 - p == attr_len) {
            bh_memcpy_s(p, attr_len, attr_buf, attr_len);
            attr_container_free(attr_buf);
            return true;
        }

        if ((uint32_t)(p1 - p + msg_end - attr_end) >= attr_len) {
            memmove(p, p1, attr_end - p1);
            bh_memcpy_s(p + (attr_end - p1), attr_len, attr_buf, attr_len);
            attr_container_free(attr_buf);
            return true;
        }

        total_length += attr_len + 100;
        if (!(attr_cont1 = attr_container_malloc(offsetof(attr_container_t, buf)
                                                 + total_length))) {
            attr_container_printf(
                "Set attr failed: allocate memory failed.\r\n");
            attr_container_free(attr_buf);
            return false;
        }

        bh_memcpy_s(attr_cont1, p - (char *)attr_cont, attr_cont,
                    p - (char *)attr_cont);
        bh_memcpy_s((char *)attr_cont1 + (unsigned)(p - (char *)attr_cont),
                    attr_end - p1, p1, attr_end - p1);
        bh_memcpy_s((char *)attr_cont1 + (unsigned)(p - (char *)attr_cont)
                        + (unsigned)(attr_end - p1),
                    attr_len, attr_buf, attr_len);
        p = attr_cont1->buf;
        set_uint32(p, total_length);
        *p_attr_cont = attr_cont1;
        /* Free original buffer */
        attr_container_free(attr_cont);
        attr_container_free(attr_buf);
        return true;
    }
    else {
        /* key not found */
        if ((uint32_t)(msg_end - attr_end) >= attr_len) {
            bh_memcpy_s(attr_end, msg_end - attr_end, attr_buf, attr_len);
            attr_container_inc_attr_num(attr_cont);
            attr_container_free(attr_buf);
            return true;
        }

        total_length += attr_len + 100;
        if (!(attr_cont1 = attr_container_malloc(offsetof(attr_container_t, buf)
                                                 + total_length))) {
            attr_container_printf(
                "Set attr failed: allocate memory failed.\r\n");
            attr_container_free(attr_buf);
            return false;
        }

        bh_memcpy_s(attr_cont1, attr_end - (char *)attr_cont, attr_cont,
                    attr_end - (char *)attr_cont);
        bh_memcpy_s((char *)attr_cont1
                        + (unsigned)(attr_end - (char *)attr_cont),
                    attr_len, attr_buf, attr_len);
        attr_container_inc_attr_num(attr_cont1);
        p = attr_cont1->buf;
        set_uint32(p, total_length);
        *p_attr_cont = attr_cont1;
        /* Free original buffer */
        attr_container_free(attr_cont);
        attr_container_free(attr_buf);
        return true;
    }

    return false;
}

bool
attr_container_set_short(attr_container_t **p_attr_cont, const char *key,
                         short value)
{
    return attr_container_set_attr(p_attr_cont, key, ATTR_TYPE_SHORT, &value,
                                   2);
}

bool
attr_container_set_int16(attr_container_t **p_attr_cont, const char *key,
                         int16_t value)
{
    return attr_container_set_attr(p_attr_cont, key, ATTR_TYPE_INT16, &value,
                                   2);
}

bool
attr_container_set_int(attr_container_t **p_attr_cont, const char *key,
                       int value)
{
    return attr_container_set_attr(p_attr_cont, key, ATTR_TYPE_INT, &value, 4);
}

bool
attr_container_set_int32(attr_container_t **p_attr_cont, const char *key,
                         int32_t value)
{
    return attr_container_set_attr(p_attr_cont, key, ATTR_TYPE_INT32, &value,
                                   4);
}

bool
attr_container_set_uint32(attr_container_t **p_attr_cont, const char *key,
                          uint32_t value)
{
    return attr_container_set_attr(p_attr_cont, key, ATTR_TYPE_UINT32, &value,
                                   4);
}

bool
attr_container_set_int64(attr_container_t **p_attr_cont, const char *key,
                         int64_t value)
{
    return attr_container_set_attr(p_attr_cont, key, ATTR_TYPE_INT64, &value,
                                   8);
}

bool
attr_container_set_uint64(attr_container_t **p_attr_cont, const char *key,
                          uint64_t value)
{
    return attr_container_set_attr(p_attr_cont, key, ATTR_TYPE_UINT64, &value,
                                   8);
}

bool
attr_container_set_byte(attr_container_t **p_attr_cont, const char *key,
                        int8_t value)
{
    return attr_container_set_attr(p_attr_cont, key, ATTR_TYPE_BYTE, &value, 1);
}

bool
attr_container_set_int8(attr_container_t **p_attr_cont, const char *key,
                        int8_t value)
{
    return attr_container_set_attr(p_attr_cont, key, ATTR_TYPE_INT8, &value, 1);
}

bool
attr_container_set_uint8(attr_container_t **p_attr_cont, const char *key,
                         uint8_t value)
{
    return attr_container_set_attr(p_attr_cont, key, ATTR_TYPE_UINT8, &value,
                                   1);
}

bool
attr_container_set_uint16(attr_container_t **p_attr_cont, const char *key,
                          uint16_t value)
{
    return attr_container_set_attr(p_attr_cont, key, ATTR_TYPE_UINT16, &value,
                                   2);
}

bool
attr_container_set_float(attr_container_t **p_attr_cont, const char *key,
                         float value)
{
    return attr_container_set_attr(p_attr_cont, key, ATTR_TYPE_FLOAT, &value,
                                   4);
}

bool
attr_container_set_double(attr_container_t **p_attr_cont, const char *key,
                          double value)
{
    return attr_container_set_attr(p_attr_cont, key, ATTR_TYPE_DOUBLE, &value,
                                   8);
}

bool
attr_container_set_bool(attr_container_t **p_attr_cont, const char *key,
                        bool value)
{
    int8_t value1 = value ? 1 : 0;
    return attr_container_set_attr(p_attr_cont, key, ATTR_TYPE_BOOLEAN, &value1,
                                   1);
}

bool
attr_container_set_string(attr_container_t **p_attr_cont, const char *key,
                          const char *value)
{
    if (!value) {
        attr_container_printf("Set attr failed: invald input arguments.\r\n");
        return false;
    }
    return attr_container_set_attr(p_attr_cont, key, ATTR_TYPE_STRING, value,
                                   strlen(value) + 1);
}

bool
attr_container_set_bytearray(attr_container_t **p_attr_cont, const char *key,
                             const int8_t *value, unsigned length)
{
    if (!value) {
        attr_container_printf("Set attr failed: invald input arguments.\r\n");
        return false;
    }
    return attr_container_set_attr(p_attr_cont, key, ATTR_TYPE_BYTEARRAY, value,
                                   length);
}

static const char *
attr_container_get_attr(const attr_container_t *attr_cont, const char *key)
{
    const char *attr_addr;

    if (!attr_cont || !key) {
        attr_container_printf(
            "Get attribute failed: invalid input arguments.\r\n");
        return NULL;
    }

    if (!(attr_addr = attr_container_find_attr(attr_cont, key))) {
        attr_container_printf("Get attribute failed: lookup key failed.\r\n");
        return NULL;
    }

    /* key len + key + '\0' */
    return attr_addr + 2 + strlen(key) + 1;
}

#define TEMPLATE_ATTR_BUF_TO_VALUE(attr, key, var_name)                      \
    do {                                                                     \
        jvalue val;                                                          \
        const char *addr = attr_container_get_attr(attr, key);               \
        uint8_t type;                                                        \
        if (!addr)                                                           \
            return 0;                                                        \
        val.i64 = 0;                                                         \
        type = *(uint8_t *)addr++;                                           \
        switch (type) {                                                      \
            case ATTR_TYPE_BYTE:  /* = ATTR_TYPE_INT8 */                     \
            case ATTR_TYPE_SHORT: /* = ATTR_TYPE_INT16 */                    \
            case ATTR_TYPE_INT:   /* = ATTR_TYPE_INT32 */                    \
            case ATTR_TYPE_INT64:                                            \
            case ATTR_TYPE_UINT8:                                            \
            case ATTR_TYPE_UINT16:                                           \
            case ATTR_TYPE_UINT32:                                           \
            case ATTR_TYPE_UINT64:                                           \
            case ATTR_TYPE_FLOAT:                                            \
            case ATTR_TYPE_DOUBLE:                                           \
            case ATTR_TYPE_BOOLEAN:                                          \
                bh_memcpy_s(&val, sizeof(val.var_name), addr,                \
                            1 << (type & 3));                                \
                break;                                                       \
            case ATTR_TYPE_STRING:                                           \
            {                                                                \
                unsigned len = get_uint16(addr);                             \
                addr += 2;                                                   \
                if (len > sizeof(val.var_name))                              \
                    len = sizeof(val.var_name);                              \
                bh_memcpy_s(&val.var_name, sizeof(val.var_name), addr, len); \
                break;                                                       \
            }                                                                \
            case ATTR_TYPE_BYTEARRAY:                                        \
            {                                                                \
                unsigned len = get_uint32(addr);                             \
                addr += 4;                                                   \
                if (len > sizeof(val.var_name))                              \
                    len = sizeof(val.var_name);                              \
                bh_memcpy_s(&val.var_name, sizeof(val.var_name), addr, len); \
                break;                                                       \
            }                                                                \
            default:                                                         \
                bh_assert(0);                                                \
                break;                                                       \
        }                                                                    \
        return val.var_name;                                                 \
    } while (0)

short
attr_container_get_as_short(const attr_container_t *attr_cont, const char *key)
{
    TEMPLATE_ATTR_BUF_TO_VALUE(attr_cont, key, i16);
}

int16_t
attr_container_get_as_int16(const attr_container_t *attr_cont, const char *key)
{
    return (int16_t)attr_container_get_as_short(attr_cont, key);
}

int
attr_container_get_as_int(const attr_container_t *attr_cont, const char *key)
{
    TEMPLATE_ATTR_BUF_TO_VALUE(attr_cont, key, i32);
}

int32_t
attr_container_get_as_int32(const attr_container_t *attr_cont, const char *key)
{
    return (int32_t)attr_container_get_as_int(attr_cont, key);
}

uint32_t
attr_container_get_as_uint32(const attr_container_t *attr_cont, const char *key)
{
    return (uint32_t)attr_container_get_as_int(attr_cont, key);
}

int64_t
attr_container_get_as_int64(const attr_container_t *attr_cont, const char *key)
{
    TEMPLATE_ATTR_BUF_TO_VALUE(attr_cont, key, i64);
}

uint64_t
attr_container_get_as_uint64(const attr_container_t *attr_cont, const char *key)
{
    return (uint64_t)attr_container_get_as_int64(attr_cont, key);
}

int8_t
attr_container_get_as_byte(const attr_container_t *attr_cont, const char *key)
{
    TEMPLATE_ATTR_BUF_TO_VALUE(attr_cont, key, i8);
}

int8_t
attr_container_get_as_int8(const attr_container_t *attr_cont, const char *key)
{
    return attr_container_get_as_byte(attr_cont, key);
}

uint8_t
attr_container_get_as_uint8(const attr_container_t *attr_cont, const char *key)
{
    return (uint8_t)attr_container_get_as_byte(attr_cont, key);
}

uint16_t
attr_container_get_as_uint16(const attr_container_t *attr_cont, const char *key)
{
    return (uint16_t)attr_container_get_as_short(attr_cont, key);
}

float
attr_container_get_as_float(const attr_container_t *attr_cont, const char *key)
{
    TEMPLATE_ATTR_BUF_TO_VALUE(attr_cont, key, f);
}

double
attr_container_get_as_double(const attr_container_t *attr_cont, const char *key)
{
    TEMPLATE_ATTR_BUF_TO_VALUE(attr_cont, key, d);
}

bool
attr_container_get_as_bool(const attr_container_t *attr_cont, const char *key)
{
    TEMPLATE_ATTR_BUF_TO_VALUE(attr_cont, key, z);
}

const int8_t *
attr_container_get_as_bytearray(const attr_container_t *attr_cont,
                                const char *key, unsigned *array_length)
{
    const char *addr = attr_container_get_attr(attr_cont, key);
    uint8_t type;
    uint32_t length;

    if (!addr)
        return NULL;

    if (!array_length) {
        attr_container_printf("Get attribute failed: invalid input arguments.");
        return NULL;
    }

    type = *(uint8_t *)addr++;
    switch (type) {
        case ATTR_TYPE_BYTE:  /* = ATTR_TYPE_INT8 */
        case ATTR_TYPE_SHORT: /* = ATTR_TYPE_INT16 */
        case ATTR_TYPE_INT:   /* = ATTR_TYPE_INT32 */
        case ATTR_TYPE_INT64:
        case ATTR_TYPE_UINT8:
        case ATTR_TYPE_UINT16:
        case ATTR_TYPE_UINT32:
        case ATTR_TYPE_UINT64:
        case ATTR_TYPE_FLOAT:
        case ATTR_TYPE_DOUBLE:
        case ATTR_TYPE_BOOLEAN:
            length = 1 << (type & 3);
            break;
        case ATTR_TYPE_STRING:
            length = get_uint16(addr);
            addr += 2;
            break;
        case ATTR_TYPE_BYTEARRAY:
            length = get_uint32(addr);
            addr += 4;
            break;
        default:
            return NULL;
    }

    *array_length = length;
    return (const int8_t *)addr;
}

char *
attr_container_get_as_string(const attr_container_t *attr_cont, const char *key)
{
    unsigned array_length;
    return (char *)attr_container_get_as_bytearray(attr_cont, key,
                                                   &array_length);
}

const char *
attr_container_get_tag(const attr_container_t *attr_cont)
{
    return attr_cont ? attr_cont->buf + sizeof(uint32_t) + sizeof(uint16_t)
                     : NULL;
}

bool
attr_container_contain_key(const attr_container_t *attr_cont, const char *key)
{
    if (!attr_cont || !key || !strlen(key)) {
        attr_container_printf(
            "Check contain key failed: invalid input arguments.\r\n");
        return false;
    }
    return attr_container_find_attr(attr_cont, key) ? true : false;
}

unsigned int
attr_container_get_serialize_length(const attr_container_t *attr_cont)
{
    const char *p;

    if (!attr_cont) {
        attr_container_printf("Get container serialize length failed: invalid "
                              "input arguments.\r\n");
        return 0;
    }

    p = attr_cont->buf;
    return sizeof(uint16_t) + get_uint32(p);
}

bool
attr_container_serialize(char *buf, const attr_container_t *attr_cont)
{
    const char *p;
    uint16_t flags;
    uint32_t length;

    if (!buf || !attr_cont) {
        attr_container_printf(
            "Container serialize failed: invalid input arguments.\r\n");
        return false;
    }

    p = attr_cont->buf;
    length = sizeof(uint16_t) + get_uint32(p);
    bh_memcpy_s(buf, length, attr_cont, length);
    /* Set readonly */
    flags = get_uint16((const char *)attr_cont);
    set_uint16(buf, flags | (1 << ATTR_CONT_READONLY_SHIFT));

    return true;
}

bool
attr_container_is_constant(const attr_container_t *attr_cont)
{
    uint16_t flags;

    if (!attr_cont) {
        attr_container_printf(
            "Container check const: invalid input arguments.\r\n");
        return false;
    }

    flags = get_uint16((const char *)attr_cont);
    return (flags & (1 << ATTR_CONT_READONLY_SHIFT)) ? true : false;
}

void
attr_container_dump(const attr_container_t *attr_cont)
{
    uint32_t total_length;
    uint16_t attr_num, i, type;
    const char *p, *tag, *key;
    jvalue value;

    if (!attr_cont)
        return;

    tag = attr_container_get_tag(attr_cont);
    if (!tag)
        return;

    attr_container_printf("Attribute container dump:\n");
    attr_container_printf("Tag: %s\n", tag);

    p = attr_container_get_attr_begin(attr_cont, &total_length, &attr_num);
    if (!p)
        return;

    attr_container_printf("Attribute list:\n");
    for (i = 0; i < attr_num; i++) {
        key = p + 2;
        /* Skip key len and key */
        p += 2 + get_uint16(p);
        type = *p++;
        attr_container_printf("  key: %s", key);

        switch (type) {
            case ATTR_TYPE_BYTE: /* = ATTR_TYPE_INT8 */
                bh_memcpy_s(&value.i8, 1, p, 1);
                attr_container_printf(", type: byte, value: 0x%x\n",
                                      value.i8 & 0xFF);
                p++;
                break;
            case ATTR_TYPE_SHORT: /* = ATTR_TYPE_INT16 */
                bh_memcpy_s(&value.i16, sizeof(int16_t), p, sizeof(int16_t));
                attr_container_printf(", type: short, value: 0x%x\n",
                                      value.i16 & 0xFFFF);
                p += 2;
                break;
            case ATTR_TYPE_INT: /* = ATTR_TYPE_INT32 */
                bh_memcpy_s(&value.i32, sizeof(int32_t), p, sizeof(int32_t));
                attr_container_printf(", type: int, value: 0x%x\n", value.i32);
                p += 4;
                break;
            case ATTR_TYPE_INT64:
                bh_memcpy_s(&value.i64, sizeof(int64_t), p, sizeof(int64_t));
                attr_container_printf(", type: int64, value: 0x%llx\n",
                                      (long long unsigned int)(value.i64));
                p += 8;
                break;
            case ATTR_TYPE_UINT8:
                bh_memcpy_s(&value.u8, 1, p, 1);
                attr_container_printf(", type: uint8, value: 0x%x\n", value.u8);
                p++;
                break;
            case ATTR_TYPE_UINT16:
                bh_memcpy_s(&value.u16, sizeof(uint16_t), p, sizeof(uint16_t));
                attr_container_printf(", type: uint16, value: 0x%x\n",
                                      value.u16);
                p += 2;
                break;
            case ATTR_TYPE_UINT32:
                bh_memcpy_s(&value.u32, sizeof(uint32_t), p, sizeof(uint32_t));
                attr_container_printf(", type: uint32, value: 0x%x\n",
                                      value.u32);
                p += 4;
                break;
            case ATTR_TYPE_UINT64:
                bh_memcpy_s(&value.u64, sizeof(uint64_t), p, sizeof(uint64_t));
                attr_container_printf(", type: int64, value: 0x%llx\n",
                                      (long long unsigned int)(value.u64));
                p += 8;
                break;
            case ATTR_TYPE_FLOAT:
                bh_memcpy_s(&value.f, sizeof(float), p, sizeof(float));
                attr_container_printf(", type: float, value: %f\n", value.f);
                p += 4;
                break;
            case ATTR_TYPE_DOUBLE:
                bh_memcpy_s(&value.d, sizeof(double), p, sizeof(double));
                attr_container_printf(", type: double, value: %f\n", value.d);
                p += 8;
                break;
            case ATTR_TYPE_BOOLEAN:
                bh_memcpy_s(&value.z, 1, p, 1);
                attr_container_printf(", type: bool, value: 0x%x\n", value.z);
                p++;
                break;
            case ATTR_TYPE_STRING:
                attr_container_printf(", type: string, value: %s\n",
                                      p + sizeof(uint16_t));
                p += sizeof(uint16_t) + get_uint16(p);
                break;
            case ATTR_TYPE_BYTEARRAY:
                attr_container_printf(", type: byte array, length: %d\n",
                                      get_uint32(p));
                p += sizeof(uint32_t) + get_uint32(p);
                break;
            default:
                bh_assert(0);
                break;
        }
    }

    attr_container_printf("\n");
}
