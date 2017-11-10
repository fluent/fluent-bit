/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2016 Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#include "rdvarint.h"
#include "rdunittest.h"


/**
 * @brief Read a varint-encoded signed integer from \p slice.
 */
size_t rd_varint_dec_slice (rd_slice_t *slice, int64_t *nump) {
        size_t num = 0;
        int shift = 0;
        unsigned char oct;

        /* FIXME: Optimize to use something better than read() */
        do {
                size_t r = rd_slice_read(slice, &oct, sizeof(oct));
                if (unlikely(r == 0))
                        return 0; /* Underflow */
                num |= (uint64_t)(oct & 0x7f) << shift;
                shift += 7;
        } while (oct & 0x80);

        *nump = (int64_t)((num >> 1) ^ -(int64_t)(num & 1));

        return shift / 7;
}





static int do_test_rd_uvarint_enc_i64 (const char *file, int line,
                                       int64_t num, const char *exp,
                                       size_t exp_size) {
        char buf[16] = { 0xff, 0xff, 0xff, 0xff,
                         0xff, 0xff, 0xff, 0xff,
                         0xff, 0xff, 0xff, 0xff,
                         0xff, 0xff, 0xff, 0xff };
        size_t sz = rd_uvarint_enc_i64(buf, sizeof(buf), num);
        size_t r;
        int ir;
        rd_buf_t b;
        rd_slice_t slice, bad_slice;
        int64_t ret_num;

        if (sz != exp_size || memcmp(buf, exp, exp_size))
                RD_UT_FAIL("i64 encode of %"PRId64": "
                           "expected size %"PRIusz" (got %"PRIusz")\n",
                           num, exp_size, sz);

        /* Verify with standard decoder */
        r = rd_varint_dec_i64(buf, sz, &ret_num);
        RD_UT_ASSERT(!RD_UVARINT_DEC_FAILED(r),
                     "varint decode failed: %"PRIusz, r);
        RD_UT_ASSERT(ret_num == num,
                     "varint decode returned wrong number: "
                     "%"PRId64" != %"PRId64, ret_num, num);

        /* Verify with slice decoder */
        rd_buf_init(&b, 1, 0);
        rd_buf_push(&b, buf, sz, NULL);
        rd_slice_init_full(&slice, &b);

        /* Should fail for incomplete reads */
        ir = rd_slice_narrow_copy(&slice, &bad_slice,
                                  rd_slice_remains(&slice)-1);
        RD_UT_ASSERT(ir, "narrow_copy failed");
        ret_num = -1;
        r = rd_varint_dec_slice(&bad_slice, &ret_num);
        RD_UT_ASSERT(RD_UVARINT_DEC_FAILED(r),
                     "varint decode failed should have failed, returned %"PRIusz,
                     r);

        /* Verify proper slice */
        ret_num = -1;
        r = rd_varint_dec_slice(&slice, &ret_num);
        RD_UT_ASSERT(!RD_UVARINT_DEC_FAILED(r),
                     "varint decode failed: %"PRIusz, r);
        RD_UT_ASSERT(ret_num == num,
                     "varint decode returned wrong number: "
                     "%"PRId64" != %"PRId64, ret_num, num);

        rd_buf_destroy(&b);

        RD_UT_PASS();
}


int unittest_rdvarint (void) {
        int fails = 0;

        fails += do_test_rd_uvarint_enc_i64(__FILE__, __LINE__, 23,
                                            (const char[]){ 23<<1 }, 1);
        fails += do_test_rd_uvarint_enc_i64(__FILE__, __LINE__, 253,
                                            (const char[]){ 0xfa,  3 }, 2);

        return fails;
}
