/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#include <fluent-bit/flb_info.h>

#include "miniz.h"

void *flb_gzip_compress(void *data, size_t len, size_t *out_len)
{
    int flush;
    int status;
    int buf_len;
    void *buf;
    z_stream strm;

    /* Allocate buffer */
    buf_len = len + 32;
    buf = malloc(buf_len);
    if (!buf) {
        return NULL;
    }

    /*
     * Miniz don't support GZip format directly, instead we will:
     *
     * - append manual GZip magic bytes
     * - inflate raw content
     * - append manual CRC32 data
     */

    /* GZIP Magic bytes */
    uint8_t *pb = buf;

    pb[0] = 0x1F;
    pb[1] = 0x8B;
    pb[2] = 8;
    pb[3] = 0;
    pb[4] = 0;
    pb[5] = 0;
    pb[6] = 0;
    pb[7] = 0;
    pb[8] = 0;
    pb[9] = 0xFF;
    pb += 10;

    /* Prepare streaming buffer context */
    memset(&strm, '\0', sizeof(strm));
    strm.zalloc = Z_NULL;
    strm.zfree  = Z_NULL;
    strm.opaque = Z_NULL;
    strm.next_in   = data;
    strm.avail_in  = len;
    strm.total_out = 0;

    flush = Z_NO_FLUSH;
    deflateInit2(&strm, Z_DEFAULT_COMPRESSION,
                 Z_DEFLATED, -Z_DEFAULT_WINDOW_BITS, 9, Z_DEFAULT_STRATEGY);

    while (1) {
        strm.next_out  = pb + strm.total_out;
        strm.avail_out = buf_len - strm.total_out;

        if (strm.avail_in == 0) {
            flush = Z_FINISH;
        }

        status = deflate(&strm, flush);
        if (status == Z_STREAM_END) {
            break;
        }
        else if (status != Z_OK) {
            deflateEnd(&strm);
            free(buf);
            return NULL;
        }
    }

    if (deflateEnd(&strm) != Z_OK) {
        free(buf);
        return NULL;
    }
    *out_len = strm.total_out;

    /* Construct the GZip CRC32 (footer) */
    mz_ulong crc;
    int footer_start = strm.total_out + 10;

    crc = mz_crc32(MZ_CRC32_INIT, data, len);
    pb = buf;
    pb[footer_start] = crc & 0xFF;
    pb[footer_start + 1] = (crc >> 8) & 0xFF;
    pb[footer_start + 2] = (crc >> 16) & 0xFF;
    pb[footer_start + 3] = (crc >> 24) & 0xFF;
    pb[footer_start + 4] = len & 0xFF;
    pb[footer_start + 5] = (len >> 8) & 0xFF;
    pb[footer_start + 6] = (len >> 16) & 0xFF;
    pb[footer_start + 7] = (len >> 24) & 0xFF;

    /* Set the real buffer size for the caller */
    *out_len += 10 + 8;

    return buf;
}