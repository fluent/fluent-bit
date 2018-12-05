/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018 Eduardo Silva <eduardo@monkey.io>
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

#ifndef CIO_SHA1_H
#define CIO_SHA1_H

#include <sha1/sha1.h>

struct cio_sha1 {
    SHA_CTX sha;
};

void cio_sha1_init(struct cio_sha1 *ctx);
void cio_sha1_update(struct cio_sha1 *ctx, const void *data, unsigned long len);
void cio_sha1_final(unsigned char hash[20], struct cio_sha1 *ctx);
void cio_sha1_hash(const void *data_in, unsigned long length,
                   unsigned char *data_out, void *state);
void cio_sha1_to_hex(unsigned char *in, char *out);

#endif
