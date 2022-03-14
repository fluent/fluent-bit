/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

/**
 * \file base64.h
 *
 * \brief RFC 1521 base64 encoding/decoding
 */

/* This code is based on base64.h from the mbedtls-2.25.0 Library distribution,
 * as originally written by Paul Bakker, et al., and forked by the Fluent Bit
 * project to provide performant base64 encoding and decoding routines.
 * The 2.25.0 implementation is included rather than 2.26.0+ implementation due
 * to performance degradation introduced in 2.26.0.
 *
 * Method and variable names are changed by the Fluent Bit authors to maintain
 * consistency with the Fluent Bit project.
 * The self test section of the code was removed by the Fluent Bit authors.
 * Other minor changes are made by the Fluent Bit authors.
 *
 * The original source file base64.h is copyright and licensed as follows;
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_BASE64_H
#define FLB_BASE64_H

#include <stddef.h>

#define FLB_BASE64_ERR_BUFFER_TOO_SMALL               -0x002A  /**< Output buffer too small. */
#define FLB_BASE64_ERR_INVALID_CHARACTER              -0x002C  /**< Invalid character in input. */

/**
 * \brief          Encode a buffer into base64 format
 *
 * \param dst      destination buffer
 * \param dlen     size of the destination buffer
 * \param olen     number of bytes written
 * \param src      source buffer
 * \param slen     amount of data to be encoded
 *
 * \return         0 if successful, or FLB_BASE64_ERR_BUFFER_TOO_SMALL.
 *                 *olen is always updated to reflect the amount
 *                 of data that has (or would have) been written.
 *                 If that length cannot be represented, then no data is
 *                 written to the buffer and *olen is set to the maximum
 *                 length representable as a size_t.
 *
 * \note           Call this function with dlen = 0 to obtain the
 *                 required buffer size in *olen
 */
int flb_base64_encode( unsigned char *dst, size_t dlen, size_t *olen,
                   const unsigned char *src, size_t slen );

/**
 * \brief          Decode a base64-formatted buffer
 *
 * \param dst      destination buffer (can be NULL for checking size)
 * \param dlen     size of the destination buffer
 * \param olen     number of bytes written
 * \param src      source buffer
 * \param slen     amount of data to be decoded
 *
 * \return         0 if successful, FLB_BASE64_ERR_BUFFER_TOO_SMALL, or
 *                 FLB_BASE64_ERR_INVALID_CHARACTER if the input data is
 *                 not correct. *olen is always updated to reflect the amount
 *                 of data that has (or would have) been written.
 *
 * \note           Call this function with *dst = NULL or dlen = 0 to obtain
 *                 the required buffer size in *olen
 */
int flb_base64_decode( unsigned char *dst, size_t dlen, size_t *olen,
                   const unsigned char *src, size_t slen );

#endif /* base64.h */
