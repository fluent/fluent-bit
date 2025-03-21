/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "host_tool_utils.h"
#include "bi-inc/shared_utils.h"
#include "bh_platform.h"

#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

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
    return get_int16(buf);
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
    return get_int32(buf);
}

char *
attr_container_get_attr_begin(const attr_container_t *attr_cont,
                              uint32_t *p_total_length, uint16_t *p_attr_num);

cJSON *
attr2json(const attr_container_t *attr_cont)
{
    uint32_t total_length;
    uint16_t attr_num, i, j, type;
    const char *p, *tag, *key;
    jvalue value;
    cJSON *root;

    if (!attr_cont)
        return NULL;

    root = cJSON_CreateObject();
    if (!root)
        return NULL;

    /* TODO: how to convert the tag? */
    tag = attr_container_get_tag(attr_cont);
    if (!tag)
        goto fail;

    p = attr_container_get_attr_begin(attr_cont, &total_length, &attr_num);
    if (!p)
        goto fail;

    for (i = 0; i < attr_num; i++) {
        cJSON *obj;

        key = p + 2;
        /* Skip key len and key */
        p += 2 + get_uint16(p);
        type = *p++;

        switch (type) {
            case ATTR_TYPE_BYTE: /* = ATTR_TYPE_INT8 */
                bh_memcpy_s(&value.i8, 1, p, 1);
                if (NULL == (obj = cJSON_CreateNumber(value.i8)))
                    goto fail;
                cJSON_AddItemToObject(root, key, obj);
                p++;
                break;
            case ATTR_TYPE_SHORT: /* = ATTR_TYPE_INT16 */
                bh_memcpy_s(&value.i16, sizeof(int16_t), p, sizeof(int16_t));
                if (NULL == (obj = cJSON_CreateNumber(value.i16)))
                    goto fail;
                cJSON_AddItemToObject(root, key, obj);
                /* another approach: cJSON_AddNumberToObject(root, key, value.s)
                 */
                p += 2;
                break;
            case ATTR_TYPE_INT: /* = ATTR_TYPE_INT32 */
                bh_memcpy_s(&value.i32, sizeof(int32_t), p, sizeof(int32_t));
                if (NULL == (obj = cJSON_CreateNumber(value.i32)))
                    goto fail;
                cJSON_AddItemToObject(root, key, obj);
                p += 4;
                break;
            case ATTR_TYPE_INT64:
                bh_memcpy_s(&value.i64, sizeof(int64_t), p, sizeof(int64_t));
                if (NULL == (obj = cJSON_CreateNumber(value.i64)))
                    goto fail;
                cJSON_AddItemToObject(root, key, obj);
                p += 8;
                break;
            case ATTR_TYPE_UINT8:
                bh_memcpy_s(&value.u8, 1, p, 1);
                if (NULL == (obj = cJSON_CreateNumber(value.u8)))
                    goto fail;
                cJSON_AddItemToObject(root, key, obj);
                p++;
                break;
            case ATTR_TYPE_UINT16:
                bh_memcpy_s(&value.u16, sizeof(uint16_t), p, sizeof(uint16_t));
                if (NULL == (obj = cJSON_CreateNumber(value.u16)))
                    goto fail;
                cJSON_AddItemToObject(root, key, obj);
                p += 2;
                break;
            case ATTR_TYPE_UINT32:
                bh_memcpy_s(&value.u32, sizeof(uint32_t), p, sizeof(uint32_t));
                if (NULL == (obj = cJSON_CreateNumber(value.u32)))
                    goto fail;
                cJSON_AddItemToObject(root, key, obj);
                p += 4;
                break;
            case ATTR_TYPE_UINT64:
                bh_memcpy_s(&value.u64, sizeof(uint64_t), p, sizeof(uint64_t));
                if (NULL == (obj = cJSON_CreateNumber(value.u64)))
                    goto fail;
                cJSON_AddItemToObject(root, key, obj);
                p += 8;
                break;
            case ATTR_TYPE_FLOAT:
                bh_memcpy_s(&value.f, sizeof(float), p, sizeof(float));
                if (NULL == (obj = cJSON_CreateNumber(value.f)))
                    goto fail;
                cJSON_AddItemToObject(root, key, obj);
                p += 4;
                break;
            case ATTR_TYPE_DOUBLE:
                bh_memcpy_s(&value.d, sizeof(double), p, sizeof(double));
                if (NULL == (obj = cJSON_CreateNumber(value.d)))
                    goto fail;
                cJSON_AddItemToObject(root, key, obj);
                p += 8;
                break;
            case ATTR_TYPE_BOOLEAN:
                bh_memcpy_s(&value.z, 1, p, 1);
                if (NULL == (obj = cJSON_CreateBool(value.z)))
                    goto fail;
                cJSON_AddItemToObject(root, key, obj);
                p++;
                break;
            case ATTR_TYPE_STRING:
                if (NULL == (obj = cJSON_CreateString(p + sizeof(uint16_t))))
                    goto fail;
                cJSON_AddItemToObject(root, key, obj);
                p += sizeof(uint16_t) + get_uint16(p);
                break;
            case ATTR_TYPE_BYTEARRAY:
                if (NULL == (obj = cJSON_CreateArray()))
                    goto fail;
                cJSON_AddItemToObject(root, key, obj);
                for (j = 0; j < get_uint32(p); j++) {
                    cJSON *item =
                        cJSON_CreateNumber(*(p + sizeof(uint32_t) + j));
                    if (item == NULL)
                        goto fail;
                    cJSON_AddItemToArray(obj, item);
                }
                p += sizeof(uint32_t) + get_uint32(p);
                break;
        }
    }

    return root;

fail:
    cJSON_Delete(root);
    return NULL;
}

attr_container_t *
json2attr(const cJSON *json_obj)
{
    attr_container_t *attr_cont;
    cJSON *item;

    if (NULL == (attr_cont = attr_container_create("")))
        return NULL;

    if (!cJSON_IsObject(json_obj))
        goto fail;

    cJSON_ArrayForEach(item, json_obj)
    {

        if (cJSON_IsNumber(item)) {
            attr_container_set_double(&attr_cont, item->string,
                                      item->valuedouble);
        }
        else if (cJSON_IsTrue(item)) {
            attr_container_set_bool(&attr_cont, item->string, true);
        }
        else if (cJSON_IsFalse(item)) {
            attr_container_set_bool(&attr_cont, item->string, false);
        }
        else if (cJSON_IsString(item)) {
            attr_container_set_string(&attr_cont, item->string,
                                      item->valuestring);
        }
        else if (cJSON_IsArray(item)) {
            int8_t *array;
            int i = 0, len = sizeof(int8_t) * cJSON_GetArraySize(item);
            cJSON *array_item;

            if (0 == len || NULL == (array = (int8_t *)malloc(len)))
                goto fail;
            memset(array, 0, len);

            cJSON_ArrayForEach(array_item, item)
            {
                /* must be number array */
                if (!cJSON_IsNumber(array_item))
                    break;
                /* TODO: if array_item->valuedouble > 127 or < -128 */
                array[i++] = (int8_t)array_item->valuedouble;
            }
            if (i > 0)
                attr_container_set_bytearray(&attr_cont, item->string, array,
                                             i);
            free(array);
        }
    }

    return attr_cont;

fail:
    attr_container_destroy(attr_cont);
    return NULL;
}

int g_mid = 0;

int
gen_random_id()
{
    static bool init = false;
    int r;

    if (!init) {
        srand(time(NULL));
        init = true;
    }

    r = rand();
    g_mid = r;

    return r;
}

char *
read_file_to_buffer(const char *filename, int *ret_size)
{
    char *buffer;
    int file;
    int file_size, read_size;
    struct stat stat_buf;

    if (!filename || !ret_size) {
        return NULL;
    }

    if ((file = open(filename, O_RDONLY, 0)) == -1) {
        return NULL;
    }

    if (fstat(file, &stat_buf) != 0) {
        close(file);
        return NULL;
    }

    file_size = stat_buf.st_size;

    if (!(buffer = malloc(file_size))) {
        close(file);
        return NULL;
    }

    read_size = read(file, buffer, file_size);
    close(file);

    if (read_size < file_size) {
        free(buffer);
        return NULL;
    }

    *ret_size = file_size;
    return buffer;
}

int
wirte_buffer_to_file(const char *filename, const char *buffer, int size)
{
    int file, ret;

    if ((file = open(filename, O_RDWR | O_CREAT | O_APPEND, 0644)) == -1)
        return -1;

    ret = write(file, buffer, size);

    close(file);

    return ret;
}
