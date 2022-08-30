/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_gzip.h>
#include <miniz/miniz.h>

#define FLB_GZIP_HEADER_OFFSET 10

typedef enum {
    FTEXT    = 1,
    FHCRC    = 2,
    FEXTRA   = 4,
    FNAME    = 8,
    FCOMMENT = 16
} flb_tinf_gzip_flag;

static unsigned int read_le16(const unsigned char *p)
{
    return ((unsigned int) p[0]) | ((unsigned int) p[1] << 8);
}

static unsigned int read_le32(const unsigned char *p)
{
    return ((unsigned int) p[0])
        | ((unsigned int) p[1] << 8)
        | ((unsigned int) p[2] << 16)
        | ((unsigned int) p[3] << 24);
}

static inline void gzip_header(void *buf)
{
    uint8_t *p;

    /* GZip Magic bytes */
    p = buf;
    *p++ = 0x1F;
    *p++ = 0x8B;
    *p++ = 8;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0xFF;
}

int flb_gzip_compress(void *in_data, size_t in_len,
                      void **out_data, size_t *out_len)
{
    int flush;
    int status;
    int footer_start;
    uint8_t *pb;
    size_t out_size;
    void *out_buf;
    z_stream strm;
    mz_ulong crc;

    /*
     * Calculating the upper bound for a gzip compression is
     * non-trivial, so we rely on miniz's own calculation
     * to guarantee memory safety.
     */
    out_size = compressBound(in_len);
    out_buf = flb_malloc(out_size);

    if (!out_buf) {
        flb_errno();
        flb_error("[gzip] could not allocate outgoing buffer");
        return -1;
    }

    /* Initialize streaming buffer context */
    memset(&strm, '\0', sizeof(strm));
    strm.zalloc    = Z_NULL;
    strm.zfree     = Z_NULL;
    strm.opaque    = Z_NULL;
    strm.next_in   = in_data;
    strm.avail_in  = in_len;
    strm.total_out = 0;

    /* Deflate mode */
    deflateInit2(&strm, Z_DEFAULT_COMPRESSION,
                 Z_DEFLATED, -Z_DEFAULT_WINDOW_BITS, 9, Z_DEFAULT_STRATEGY);

    /*
     * Miniz don't support GZip format directly, instead we will:
     *
     * - append manual GZip magic bytes
     * - deflate raw content
     * - append manual CRC32 data
     */
    gzip_header(out_buf);

    /* Header offset */
    pb = (uint8_t *) out_buf + FLB_GZIP_HEADER_OFFSET;

    flush = Z_NO_FLUSH;
    while (1) {
        strm.next_out  = pb + strm.total_out;
        strm.avail_out = out_size - (pb - (uint8_t *) out_buf);

        if (strm.avail_in == 0) {
            flush = Z_FINISH;
        }

        status = deflate(&strm, flush);
        if (status == Z_STREAM_END) {
            break;
        }
        else if (status != Z_OK) {
            deflateEnd(&strm);
            return -1;
        }
    }

    if (deflateEnd(&strm) != Z_OK) {
        flb_free(out_buf);
        return -1;
    }
    *out_len = strm.total_out;

    /* Construct the gzip checksum (CRC32 footer) */
    footer_start = FLB_GZIP_HEADER_OFFSET + *out_len;
    pb = (uint8_t *) out_buf + footer_start;

    crc = mz_crc32(MZ_CRC32_INIT, in_data, in_len);
    *pb++ = crc & 0xFF;
    *pb++ = (crc >> 8) & 0xFF;
    *pb++ = (crc >> 16) & 0xFF;
    *pb++ = (crc >> 24) & 0xFF;
    *pb++ = in_len & 0xFF;
    *pb++ = (in_len >> 8) & 0xFF;
    *pb++ = (in_len >> 16) & 0xFF;
    *pb++ = (in_len >> 24) & 0xFF;

    /* Set the real buffer size for the caller */
    *out_len += FLB_GZIP_HEADER_OFFSET + 8;
    *out_data = out_buf;

    return 0;
}

/* Uncompress (inflate) GZip data */
int flb_gzip_uncompress(void *in_data, size_t in_len,
                        void **out_data, size_t *out_len)
{
    int status;
    uint8_t *p;
    void *out_buf;
    size_t out_size = 0;
    void *zip_data;
    size_t zip_len;
    unsigned char flg;
    unsigned int xlen, hcrc;
    unsigned int dlen, crc;
    mz_ulong crc_out;
    mz_stream stream;
    const unsigned char *start;

    /* Minimal length: header + crc32 */
    if (in_len < 18) {
        flb_error("[gzip] unexpected content length");
        return -1;
    }

    /* Magic bytes */
    p = in_data;
    if (p[0] != 0x1F || p[1] != 0x8B) {
        flb_error("[gzip] invalid magic bytes");
        return -1;
    }

    if (p[2] != 8) {
        flb_error("[gzip] invalid method");
        return -1;
    }

    /* Flag byte */
    flg = p[3];

    /* Reserved bits */
    if (flg & 0xE0) {
        flb_error("[gzip] invalid flag");
        return -1;
    }

    /* Skip base header of 10 bytes */
    start = p + FLB_GZIP_HEADER_OFFSET;

    /* Skip extra data if present */
    if (flg & FEXTRA) {
        xlen = read_le16(start);
        if (xlen > in_len - 12) {
            flb_error("[gzip] invalid gzip data");
            return -1;
        }
        start += xlen + 2;
    }

    /* Skip file name if present */
    if (flg & FNAME) {
        do {
            if (start - p >= in_len) {
                flb_error("[gzip] invalid gzip data (FNAME)");
                return -1;
            }
        } while (*start++);
    }

    /* Skip file comment if present */
    if (flg & FCOMMENT) {
        do {
            if (start - p >= in_len) {
                flb_error("[gzip] invalid gzip data (FCOMMENT)");
                return -1;
            }
        } while (*start++);
    }

    /* Check header crc if present */
    if (flg & FHCRC) {
        if (start - p > in_len - 2) {
            flb_error("[gzip] invalid gzip data (FHRC)");
            return -1;
        }

        hcrc = read_le16(start);
        crc = mz_crc32(MZ_CRC32_INIT, p, start - p) & 0x0000FFFF;
        if (hcrc != crc) {
            flb_error("[gzip] invalid gzip header CRC");
            return -1;
        }
        start += 2;
    }

    /* Get decompressed length */
    dlen = read_le32(&p[in_len - 4]);

    /* Limit decompressed length to 100MB */
    if (dlen > 100000000) {
        flb_error("[gzip] maximum decompression size is 100MB");
        return -1;
    }

    /* Get CRC32 checksum of original data */
    crc = read_le32(&p[in_len - 8]);

    /* Decompress data */
    if ((p + in_len) - p < 8) {
        flb_error("[gzip] invalid gzip CRC32 checksum");
        return -1;
    }

    /* Allocate outgoing buffer */
    out_buf = flb_malloc(dlen);
    if (!out_buf) {
        flb_errno();
        return -1;
    }
    out_size = dlen;

    /* Ensure size is above 0 */
    if (((p + in_len) - start - 8) <= 0) {
        flb_free(out_buf);
        return -1;
    }

    /* Map zip content */
    zip_data = (uint8_t *) start;
    zip_len = (p + in_len) - start - 8;

    memset(&stream, 0, sizeof(stream));
    stream.next_in = zip_data;
    stream.avail_in = zip_len;
    stream.next_out = out_buf;
    stream.avail_out = out_size;

    status = mz_inflateInit2(&stream, -Z_DEFAULT_WINDOW_BITS);
    if (status != MZ_OK) {
        flb_free(out_buf);
        return -1;
    }

    status = mz_inflate(&stream, MZ_FINISH);
    if (status != MZ_STREAM_END) {
        mz_inflateEnd(&stream);
        flb_free(out_buf);
        return -1;
    }

    if (stream.total_out != dlen) {
        mz_inflateEnd(&stream);
        flb_free(out_buf);
        flb_error("[gzip] invalid gzip data size");
        return -1;
    }

    /* terminate the stream, it's not longer required */
    mz_inflateEnd(&stream);

    /* Validate message CRC vs inflated data CRC */
    crc_out = mz_crc32(MZ_CRC32_INIT, out_buf, dlen);
    if (crc_out != crc) {
        flb_free(out_buf);
        flb_error("[gzip] invalid GZip checksum (CRC32)");
        return -1;
    }

    /* set the uncompressed data */
    *out_len = dlen;
    *out_data = out_buf;

    return 0;
}
