/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018-2021 Eduardo Silva <eduardo@monkey.io>
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

#include <chunkio/chunkio.h>
#include <chunkio/cio_error.h>

char *cio_error_get_str(struct cio_chunk *ch)
{
    int err =  cio_error_get(ch);

    switch (err) {
        case CIO_ERR_BAD_CHECKSUM:
            return "bad checksum";
        case CIO_ERR_BAD_LAYOUT:
            return "bad layout or invalid header";
        case CIO_ERR_PERMISSION:
            return "permission error";
        default:
            return "no error has been specified";
    }
}

/* Return the current error number from a chunk */
int cio_error_get(struct cio_chunk *ch)
{
    return ch->error_n;
}

/* Set an error number in the chunk */
void cio_error_set(struct cio_chunk *ch, int status)
{
    ch->error_n = status;

    if (ch->ctx != NULL) {
        ch->ctx->last_chunk_error = status;
    }
}

/* Reset the error number in a chunk */
void cio_error_reset(struct cio_chunk *ch)
{
    ch->error_n = 0;
}
