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

/* Just a simple wrapper over sha1 routines */

#include <stdio.h>
#include <string.h>
#include <chunkio/cio_sha1.h>

void cio_sha1_init(struct cio_sha1 *ctx)
{
    SHA1_Init(&ctx->sha);
}

void cio_sha1_update(struct cio_sha1 *ctx, const void *data, unsigned long len)
{
    SHA1_Update(&ctx->sha, data, len);
}

void cio_sha1_final(unsigned char hash[20], struct cio_sha1 *ctx)
{
    SHA1_Final(hash, &ctx->sha);
}

void cio_sha1_hash(const void *data_in, unsigned long length,
                   unsigned char *data_out, void *state)
{
    SHA_CTX sha;
    SHA1_Init(&sha);
    SHA1_Update(&sha, data_in, length);

    /*
     * If state is not NULL, make a copy of the SHA context for future
     * iterations and updates.
     */
    if (state != NULL) {
        memcpy(state, &sha, sizeof(SHA_CTX));
    }

    SHA1_Final(data_out, &sha);
}

void cio_sha1_to_hex(unsigned char *in, char *out)
{
    int i;

    for (i = 0; i < 20; ++i) {
        sprintf(&out[i*2], "%02x", in[i]);
    }

    out[40] = '\0';
}
