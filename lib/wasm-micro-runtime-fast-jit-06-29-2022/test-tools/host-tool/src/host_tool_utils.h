/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _HOST_TOOL_UTILS_H_
#define _HOST_TOOL_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "bi-inc/attr_container.h"
#include "cJSON.h"

/**
 * @brief Convert attribute container object to cJSON object.
 *
 * @param attr the attribute container object to be converted
 *
 * @return the created cJSON object if not NULL, NULL means fail
 *
 * @warning the return object should be deleted with cJSON_Delete by caller
 */
cJSON *
attr2json(const attr_container_t *attr);

/**
 * @brief Convert cJSON object to attribute container object.
 *
 * @param json the cJSON object to be converted
 *
 * @return the created attribute container object if not NULL, NULL means fail
 *
 * @warning the return object should be deleted with attr_container_destroy
 */
attr_container_t *
json2attr(const cJSON *json);

/**
 * @brief Generate a random 32 bit integer.
 *
 * @return the generated random integer
 */
int
gen_random_id();

/**
 * @brief Read file content to buffer.
 *
 * @param filename the file name to read
 * @param ret_size pointer of integer to save file size once return success
 *
 * @return the created buffer which contains file content if not NULL, NULL
 * means fail
 *
 * @warning the return buffer should be deleted with free by caller
 */
char *
read_file_to_buffer(const char *filename, int *ret_size);

/**
 * @brief Write buffer content to file.
 *
 * @param filename name the file name to be written
 * @param buffer the buffer
 * @param size size of the buffer to be written
 *
 * @return < 0 means fail, > 0 means the number of bytes actually written
 */
int
wirte_buffer_to_file(const char *filename, const char *buffer, int size);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif
