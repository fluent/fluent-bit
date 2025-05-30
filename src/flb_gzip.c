/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_compression.h>
#include <miniz/miniz.h>
#include <stdbool.h>

#define FLB_GZIP_HEADER_OFFSET 10
#define FLB_GZIP_HEADER_SIZE   FLB_GZIP_HEADER_OFFSET

#define FLB_GZIP_MAGIC_NUMBER  0x8B1F

typedef enum {
    FTEXT    = 1,
    FHCRC    = 2,
    FEXTRA   = 4,
    FNAME    = 8,
    FCOMMENT = 16
} flb_tinf_gzip_flag;

#pragma pack(push, 1)
struct flb_gzip_header {
    uint16_t magic_number;
    uint8_t  compression_method;
    uint8_t  header_flags;
    uint32_t timestamp;
    uint8_t  compression_flags;
    uint8_t  operating_system_id;
};
#pragma pack(pop)

struct flb_gzip_decompression_context {
    struct flb_gzip_header gzip_header;
    mz_stream              miniz_stream;
};

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


#include <ctype.h>

static inline void flb_hex_dump(uint8_t *buffer, size_t buffer_length, size_t line_length) {
    char  *printable_line;
    size_t buffer_index;
    size_t filler_index;

    if (40 < line_length)
    {
        line_length = 40;
    }

    printable_line = alloca(line_length + 1);

    if (NULL == printable_line)
    {
        printf("Alloca returned NULL\n");

        return;
    }

    memset(printable_line, '\0', line_length + 1);

    for (buffer_index = 0 ; buffer_index < buffer_length ; buffer_index++) {
        if (0 != buffer_index &&
            0 == (buffer_index % line_length)) {

            printf("%s\n", printable_line);

            memset(printable_line, '\0', line_length + 1);
        }

        if (0 != isprint(buffer[buffer_index])) {
            printable_line[(buffer_index % line_length)] = buffer[buffer_index];
        }
        else {
            printable_line[(buffer_index % line_length)] = '.';
        }

        printf("%02X ", buffer[buffer_index]);
    }

    if (0 != buffer_index &&
        0 != (buffer_index % line_length)) {

        for (filler_index = 0 ;
             filler_index < (line_length - (buffer_index % line_length)) ;
             filler_index++) {
            printf("   ");
        }

        printf("%s\n", printable_line);

        memset(printable_line, '.', line_length);
    }
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


/* Stateful gzip decompressor */

static int flb_gzip_decompressor_process_header(
            struct flb_decompression_context *context)
{
    struct flb_gzip_decompression_context *inner_context;

    inner_context = (struct flb_gzip_decompression_context *) \
                        context->inner_context;

    /* Minimal length: header + crc32 */
    if (context->input_buffer_length < FLB_GZIP_HEADER_SIZE) {
        flb_error("[gzip] unexpected content length");

        return FLB_DECOMPRESSOR_FAILURE;
    }

    memcpy(&inner_context->gzip_header,
           context->read_buffer,
           FLB_GZIP_HEADER_SIZE);

    context->read_buffer = &context->read_buffer[FLB_GZIP_HEADER_SIZE];
    context->input_buffer_length -= FLB_GZIP_HEADER_SIZE;

    /* Magic bytes */
    if (inner_context->gzip_header.magic_number != FLB_GZIP_MAGIC_NUMBER) {
        context->state = FLB_DECOMPRESSOR_STATE_FAILED;

        flb_error("[gzip] invalid magic bytes : %04x",
                  inner_context->gzip_header.magic_number);

        return FLB_DECOMPRESSOR_FAILURE;
    }

    if (inner_context->gzip_header.compression_method != MZ_DEFLATED) {
        context->state = FLB_DECOMPRESSOR_STATE_FAILED;

        flb_error("[gzip] invalid method : %u",
                  inner_context->gzip_header.compression_method);

        return FLB_DECOMPRESSOR_FAILURE;
    }

    /* Flag processing */
    /* Reserved bits */
    if (inner_context->gzip_header.header_flags & 0xE0) {
        context->state = FLB_DECOMPRESSOR_STATE_FAILED;

        flb_error("[gzip] invalid flag mask : %x",
                  inner_context->gzip_header.header_flags);

        return FLB_DECOMPRESSOR_FAILURE;
    }

    context->state = FLB_DECOMPRESSOR_STATE_EXPECTING_OPTIONAL_HEADERS;

    return FLB_DECOMPRESSOR_SUCCESS;
}

static int flb_gzip_decompressor_process_optional_headers(
            struct flb_decompression_context *context)
{
    struct flb_gzip_decompression_context *inner_context;
    int                                    status;
    uint16_t                               hcrc;
    uint16_t                               xlen;
    uint16_t                               crc;

    inner_context = (struct flb_gzip_decompression_context *) \
                        context->inner_context;

    /* Skip extra data if present */
    if (inner_context->gzip_header.header_flags & FEXTRA) {
        if (context->input_buffer_length <= sizeof(uint16_t)) {
            return FLB_DECOMPRESSOR_INSUFFICIENT_DATA;
        }

        xlen = sizeof(uint16_t) + read_le16(context->read_buffer);

        if (context->input_buffer_length < xlen) {
            return FLB_DECOMPRESSOR_INSUFFICIENT_DATA;
        }

        context->read_buffer = &context->read_buffer[xlen];
        context->input_buffer_length -= xlen;

        inner_context->gzip_header.header_flags &= (~FEXTRA);
    }

    if (inner_context->gzip_header.header_flags != 0 &&
        context->input_buffer_length == 0) {
        return FLB_DECOMPRESSOR_INSUFFICIENT_DATA;
    }

    /* Skip file name if present */
    if (inner_context->gzip_header.header_flags & FNAME) {
        xlen = strnlen((char *) context->read_buffer,
                       context->input_buffer_length);

        if (xlen == 0 ||
            xlen == context->input_buffer_length) {
            return FLB_DECOMPRESSOR_INSUFFICIENT_DATA;
        }

        xlen++;

        context->read_buffer = &context->read_buffer[xlen];
        context->input_buffer_length -= xlen;

        inner_context->gzip_header.header_flags &= (~FNAME);
    }

    if (inner_context->gzip_header.header_flags != 0 &&
        context->input_buffer_length == 0) {
        return FLB_DECOMPRESSOR_INSUFFICIENT_DATA;
    }

    /* Skip file comment if present */
    if (inner_context->gzip_header.header_flags & FCOMMENT) {
        xlen = strnlen((char *) context->read_buffer,
                       context->input_buffer_length);

        if (xlen == 0 ||
            xlen == context->input_buffer_length) {
            return FLB_DECOMPRESSOR_INSUFFICIENT_DATA;
        }

        context->read_buffer = &context->read_buffer[xlen];
        context->input_buffer_length -= xlen;

        inner_context->gzip_header.header_flags &= (~FCOMMENT);
    }

    if (inner_context->gzip_header.header_flags != 0 &&
        context->input_buffer_length == 0) {
        return FLB_DECOMPRESSOR_INSUFFICIENT_DATA;
    }

    /* Check header crc if present (lower 16 bits of the checksum)*/
    if (inner_context->gzip_header.header_flags & FHCRC) {
        if (context->input_buffer_length <= sizeof(uint16_t)) {
            return FLB_DECOMPRESSOR_INSUFFICIENT_DATA;
        }

        hcrc = read_le16(context->read_buffer);

        crc = mz_crc32(MZ_CRC32_INIT,
                       (const unsigned char *) &inner_context->gzip_header,
                       FLB_GZIP_HEADER_SIZE);

        crc &= 0x0000FFFF;

        if (hcrc != crc) {
            context->state = FLB_DECOMPRESSOR_STATE_FAILED;

            return FLB_DECOMPRESSOR_CORRUPTED_HEADER;
        }

        xlen = sizeof(uint16_t);

        context->read_buffer = &context->read_buffer[xlen];
        context->input_buffer_length -= xlen;

        inner_context->gzip_header.header_flags &= (~FHCRC);
    }

    status = mz_inflateInit2(&inner_context->miniz_stream,
                             -Z_DEFAULT_WINDOW_BITS);

    if (status != MZ_OK) {
        context->state = FLB_DECOMPRESSOR_STATE_FAILED;

        return FLB_DECOMPRESSOR_FAILURE;
    }

    context->state = FLB_DECOMPRESSOR_STATE_EXPECTING_BODY;

    return FLB_DECOMPRESSOR_SUCCESS;
}

static int flb_gzip_decompressor_process_body_chunk(
                struct flb_decompression_context *context,
                void *output_buffer,
                size_t *output_length)
{
    size_t                                 processed_bytes;
    struct flb_gzip_decompression_context *inner_context;
    int                                    status;

    if (*output_length == 0) {
        return FLB_DECOMPRESSOR_SUCCESS;
    }

    inner_context = (struct flb_gzip_decompression_context *) \
                        context->inner_context;

    inner_context->miniz_stream.next_in = context->read_buffer;
    inner_context->miniz_stream.avail_in = context->input_buffer_length;
    inner_context->miniz_stream.next_out = output_buffer;
    inner_context->miniz_stream.avail_out = *output_length;

    status = mz_inflate(&inner_context->miniz_stream, MZ_PARTIAL_FLUSH);

    if (status != MZ_OK && status != MZ_STREAM_END) {
        context->state = FLB_DECOMPRESSOR_STATE_FAILED;

        mz_inflateEnd(&inner_context->miniz_stream);

        *output_length = 0;

        return FLB_DECOMPRESSOR_FAILURE;
    }

    processed_bytes  = context->input_buffer_length;
    processed_bytes -= inner_context->miniz_stream.avail_in;

    *output_length  -= inner_context->miniz_stream.avail_out;

#ifdef FLB_DECOMPRESSOR_ERASE_DECOMPRESSED_DATA
    if (processed_bytes > 0) {
        memset(context->read_buffer, 0, processed_bytes);
    }
#endif

    context->read_buffer = &context->read_buffer[processed_bytes];
    context->input_buffer_length = inner_context->miniz_stream.avail_in;

    if (status == MZ_STREAM_END) {
        mz_inflateEnd(&inner_context->miniz_stream);

        context->state = FLB_DECOMPRESSOR_STATE_EXPECTING_FOOTER;

        memset(&inner_context->miniz_stream, 0, sizeof(mz_stream));
    }

    return FLB_DECOMPRESSOR_SUCCESS;
}


static int flb_gzip_decompressor_process_footer(
            struct flb_decompression_context *context)
{
    if (context->input_buffer_length <  (sizeof(uint32_t) * 2)) {
        return FLB_DECOMPRESSOR_INSUFFICIENT_DATA;
    }

    context->input_buffer_length -= (sizeof(uint32_t) * 2);

    if (context->input_buffer_length > 0) {
        context->read_buffer = &context->read_buffer[sizeof(uint32_t) * 2];
    }
    else {
        context->read_buffer = context->input_buffer;
    }

    context->state = FLB_DECOMPRESSOR_STATE_EXPECTING_HEADER;

    return FLB_DECOMPRESSOR_SUCCESS;
}

int flb_gzip_decompressor_dispatch(struct flb_decompression_context *context,
                                   void *output_buffer,
                                   size_t *output_length)
{
    size_t output_buffer_size;
    int    status;

    output_buffer_size = *output_length;

    *output_length = 0;

    status = FLB_DECOMPRESSOR_SUCCESS;

    if (context == NULL ||
        context->inner_context == NULL) {
        status = FLB_DECOMPRESSOR_FAILURE;
    }

    if (context->input_buffer_length == 0) {
        flb_debug("[gzip] unexpected call with an empty input buffer");

        status = FLB_DECOMPRESSOR_INSUFFICIENT_DATA;
    }

    if (status == FLB_DECOMPRESSOR_SUCCESS &&
        context->state == FLB_DECOMPRESSOR_STATE_EXPECTING_HEADER) {
        status = flb_gzip_decompressor_process_header(context);
    }

    if (status == FLB_DECOMPRESSOR_SUCCESS &&
        context->state == FLB_DECOMPRESSOR_STATE_EXPECTING_OPTIONAL_HEADERS) {
        status = flb_gzip_decompressor_process_optional_headers(context);
    }

    if (status == FLB_DECOMPRESSOR_SUCCESS &&
        context->state == FLB_DECOMPRESSOR_STATE_EXPECTING_BODY) {
        *output_length = output_buffer_size;

        status = flb_gzip_decompressor_process_body_chunk(
                    context,
                    output_buffer,
                    output_length);
    }

    if (status == FLB_DECOMPRESSOR_SUCCESS &&
        context->state == FLB_DECOMPRESSOR_STATE_EXPECTING_FOOTER) {
        status = flb_gzip_decompressor_process_footer(context);
    }

    return status;
}

void *flb_gzip_decompression_context_create()
{
    struct flb_gzip_decompression_context *context;

    context = flb_calloc(1, sizeof(struct flb_gzip_decompression_context));

    if (context == NULL) {
        flb_errno();
    }

    return (void *) context;
}

void flb_gzip_decompression_context_destroy(void *context)
{
    if (context != NULL) {
        flb_free(context);
    }
}

int flb_is_http_session_gzip_compressed(struct mk_http_session *session)
{
    int gzip_compressed = FLB_FALSE;

    int i = 0;
    int extra_size = -1;
    struct mk_http_header *headers_extra;

    extra_size = session->parser.headers_extra_count;
    if (extra_size > 0) {
        for (i = 0; i < extra_size; i++) {
            headers_extra = &session->parser.headers_extra[i];
            if (headers_extra->key.len == 16 &&
                strncasecmp(headers_extra->key.data, "Content-Encoding", 16) == 0) {
                if (headers_extra->val.len == 4 &&
                    strncasecmp(headers_extra->val.data, "gzip", 4) == 0) {
                    flb_debug("body is gzipped");
                    gzip_compressed = FLB_TRUE;
                }
            }
        }
    }

    return gzip_compressed;
}

static int vaild_os_flag(const char data)
{
    uint8_t p;

    p = (uint8_t)data;
    if (p == 0x00 || /* Fat Filesystem       */
        p == 0x01 || /* Amiga                */
        p == 0x02 || /* VMS                  */
        p == 0x03 || /* Unix                 */
        p == 0x04 || /* VM/CMS               */
        p == 0x05 || /* Atari TOS            */
        p == 0x06 || /* HPFS Filesystem (OS/2, NT) */
        p == 0x07 || /* Macintosh            */
        p == 0x08 || /* Z-System             */
        p == 0x09 || /* CP/M                 */
        p == 0x0a || /* TOPS-20              */
        p == 0x0b || /* NTFS filesystem (NT) */
        p == 0x0c || /* QDOS                 */
        p == 0x0d || /* Acorn RISCOS         */
        p == 0xff)   /* Unknown              */ {

        return FLB_TRUE;
    }

    return FLB_FALSE;
}

size_t flb_gzip_count(const char *data, size_t len, size_t **out_borders, size_t border_count)
{
    int i;
    size_t count = 0;
    const uint8_t *p;
    size_t *borders = NULL;

    if (out_borders != NULL) {
        borders = *out_borders;
    }

    p = (const uint8_t *) data;
    /* search other gzip starting bits and method. */
    for (i = 2; i < len &&
                 i + 9 <= len; i++) {
        /* A vaild gzip payloads are larger than 18 bytes. */
        if (len - i < 18) {
            break;
        }

        if (p[i] == 0x1F && p[i+1] == 0x8B && p[i+2] == 8 &&
            vaild_os_flag(p[i+9])) {
            if (out_borders != NULL) {
                borders[count] = i;
            }
            count++;
        }
    }

    if (out_borders != NULL && border_count >= count) {
        /* The length of the last border refers to the original length. */
        borders[border_count] = len;
    }

    return count;
}
