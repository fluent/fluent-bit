/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2022 The Fluent Bit Authors
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

/*
 * A wrapper for the OpenSSL SHA512 functions if OpenSSL is available.
 * Otherwise, the functions in this header file provide
 * the following public domain sha512 hash implementation.
 *
 * This is based on the musl libc SHA512 implementation. Follow the
 * link for the original source code.
 * https://git.musl-libc.org/cgit/musl/tree/src/crypt/crypt_sha512.c?h=v1.1.22
 *
 * Here is how to use it:
 *
 * #include <fluent-bit/flb_sha512.h>
 *
 * void main(void)
 * {
 *     struct flb_sha512 sha512;
 *     char buf[64];
 *
 *     flb_sha512_init(&sha512);
 *     flb_sha512_update(&sha512, "aiueo", 5);
 *     flb_sha512_sum(&sha512, buf);
 * }
 */

#ifndef FLB_SHA512_H
#define FLB_SHA512_H

#include <stdint.h>
#include <fluent-bit/flb_info.h>

#ifdef FLB_HAVE_OPENSSL

#include <openssl/sha.h>

struct flb_sha512 {
	SHA512_CTX ctx;
};

#else

struct flb_sha512 {
	uint64_t len;     /* processed message length */
	uint64_t h[8];    /* hash state */
	uint8_t buf[128]; /* message block buffer */
};

#endif /* FLB_HAVE_OPENSSL */

void flb_sha512_init(struct flb_sha512 *s);
void flb_sha512_sum(struct flb_sha512 *s, uint8_t *md);
void flb_sha512_update(struct flb_sha512 *s, const void *m, unsigned long len);

#endif
