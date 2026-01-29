/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_zstd.h>
#include <fluent-bit/flb_snappy.h>

#include <fluent-bit/aws/flb_aws_compress.h>
#include "flb_tests_internal.h"

#define FLB_AWS_COMPRESS_TEST_TYPE_COMPRESS     1
#define FLB_AWS_COMPRESS_TEST_TYPE_B64_TRUNCATE 2

/* test case definition struct */
struct flb_aws_test_case {
    char* compression_keyword;
    char* in_data;
    char* expect_out_data_b64;
    int expect_ret;
};

/* test loop function declarations */
static unsigned char * base64_encode(const unsigned char *src, size_t len,
			      size_t *out_len);
static unsigned char * base64_decode(const unsigned char *src, size_t len,
			      size_t *out_len);
static void flb_aws_compress_general_test_cases(int test_type,
                                               struct flb_aws_test_case *cases,
                                               size_t max_out_len,
                                               int(*decompress)(void *in_data,
                                                               size_t in_len,
                                                               void **out_data,
                                                               size_t *out_len));
static void flb_aws_compress_test_cases(struct flb_aws_test_case *cases);
static void flb_aws_compress_truncate_b64_test_cases__gzip_decode(
                                                    struct flb_aws_test_case *cases,
                                                    size_t max_out_len);
static void flb_aws_compress_truncate_b64_test_cases__zstd_decode(
                                                    struct flb_aws_test_case *cases,
                                                    size_t max_out_len);

/** ------ Test Cases ------ **/
void test_compression_gzip()
{
    struct flb_aws_test_case cases[] =
    {
        {
            "gzip",
            "hello hello hello hello hello hello",
            "H4sIAAAAAAAA/8tIzcnJV8jARwIAVzdihSMAAAA=",
            0
        },
        { 0 }
    };

    flb_aws_compress_test_cases(cases);
}

void test_compression_zstd()
{
    struct flb_aws_test_case cases[] =
    {
        {
            "zstd",
            "hello hello hello hello hello hello",
            "KLUv/SAjZQAAMGhlbGxvIAEAuUsR",
            0
        },
        { 0 }
    };

    flb_aws_compress_test_cases(cases);
}

/*
 * Test snappy framed compression round-trip
 *
 * Uses Google's Snappy framing format specification (same as src/flb_snappy.c).
 *
 * This test validates that:
 * 1. flb_snappy_compress_framed_data() produces valid snappy framed output
 * 2. flb_snappy_uncompress_framed_data() correctly decompresses the data
 * 3. Multiple concatenated snappy chunks decompress correctly end-to-end
 * 4. The decompressed output equals the original input
 */
void test_compression_snappy()
{
    int ret;
    char *compressed_data = NULL;
    size_t compressed_len = 0;
    char *decompressed_data = NULL;
    size_t decompressed_len = 0;

    /* Test case 1: Simple string */
    const char *test_simple = "hello hello hello hello hello hello";
    size_t test_simple_len = strlen(test_simple);

    ret = flb_snappy_compress_framed_data((char *)test_simple, test_simple_len,
                                          &compressed_data, &compressed_len);
    TEST_CHECK(ret == 0);
    TEST_MSG("flb_snappy_compress_framed_data failed for simple string, ret=%d", ret);

    if (ret == 0) {
        ret = flb_snappy_uncompress_framed_data(compressed_data, compressed_len,
                                                &decompressed_data, &decompressed_len);
        TEST_CHECK(ret == 0);
        TEST_MSG("flb_snappy_uncompress_framed_data failed for simple string, ret=%d", ret);

        if (ret == 0) {
            TEST_CHECK(decompressed_len == test_simple_len);
            TEST_MSG("Length mismatch: expected %zu, got %zu", test_simple_len, decompressed_len);

            ret = memcmp(test_simple, decompressed_data, test_simple_len);
            TEST_CHECK(ret == 0);
            TEST_MSG("Content mismatch for simple string");

            flb_free(decompressed_data);
            decompressed_data = NULL;
        }
        flb_free(compressed_data);
        compressed_data = NULL;
    }

    /* Test case 2: Larger data that spans multiple blocks (>64KB to test chunking) */
    size_t large_len = 100000;  /* 100KB to ensure multiple 64KB blocks */
    char *large_data = flb_malloc(large_len);
    TEST_CHECK(large_data != NULL);

    if (large_data != NULL) {
        /* Fill with repeating pattern */
        size_t i;
        for (i = 0; i < large_len; i++) {
            large_data[i] = 'A' + (i % 26);
        }

        ret = flb_snappy_compress_framed_data(large_data, large_len,
                                              &compressed_data, &compressed_len);
        TEST_CHECK(ret == 0);
        TEST_MSG("flb_snappy_compress_framed_data failed for large data, ret=%d", ret);

        if (ret == 0) {
            ret = flb_snappy_uncompress_framed_data(compressed_data, compressed_len,
                                                    &decompressed_data, &decompressed_len);
            TEST_CHECK(ret == 0);
            TEST_MSG("flb_snappy_uncompress_framed_data failed for large data, ret=%d", ret);

            if (ret == 0) {
                TEST_CHECK(decompressed_len == large_len);
                TEST_MSG("Length mismatch for large data: expected %zu, got %zu",
                         large_len, decompressed_len);

                ret = memcmp(large_data, decompressed_data, large_len);
                TEST_CHECK(ret == 0);
                TEST_MSG("Content mismatch for large data");

                flb_free(decompressed_data);
                decompressed_data = NULL;
            }
            flb_free(compressed_data);
            compressed_data = NULL;
        }
        flb_free(large_data);
    }

    /* Test case 3: Concatenated snappy frames (simulating streaming compression) */
    const char *chunk1 = "First chunk of data for snappy compression test. ";
    const char *chunk2 = "Second chunk with different content patterns. ";
    const char *chunk3 = "Third and final chunk to complete the test sequence.";
    size_t chunk1_len = strlen(chunk1);
    size_t chunk2_len = strlen(chunk2);
    size_t chunk3_len = strlen(chunk3);
    size_t total_input_len = chunk1_len + chunk2_len + chunk3_len;

    char *compressed1 = NULL, *compressed2 = NULL, *compressed3 = NULL;
    size_t compressed1_len = 0, compressed2_len = 0, compressed3_len = 0;

    /* Compress each chunk separately */
    ret = flb_snappy_compress_framed_data((char *)chunk1, chunk1_len,
                                          &compressed1, &compressed1_len);
    TEST_CHECK(ret == 0);

    ret = flb_snappy_compress_framed_data((char *)chunk2, chunk2_len,
                                          &compressed2, &compressed2_len);
    TEST_CHECK(ret == 0);

    ret = flb_snappy_compress_framed_data((char *)chunk3, chunk3_len,
                                          &compressed3, &compressed3_len);
    TEST_CHECK(ret == 0);

    if (compressed1 && compressed2 && compressed3) {
        /* Concatenate all compressed chunks */
        size_t concat_len = compressed1_len + compressed2_len + compressed3_len;
        char *concatenated = flb_malloc(concat_len);
        TEST_CHECK(concatenated != NULL);

        if (concatenated) {
            memcpy(concatenated, compressed1, compressed1_len);
            memcpy(concatenated + compressed1_len, compressed2, compressed2_len);
            memcpy(concatenated + compressed1_len + compressed2_len,
                   compressed3, compressed3_len);

            /* Build expected decompressed output */
            char *expected = flb_malloc(total_input_len + 1);
            TEST_CHECK(expected != NULL);

            if (expected) {
                memcpy(expected, chunk1, chunk1_len);
                memcpy(expected + chunk1_len, chunk2, chunk2_len);
                memcpy(expected + chunk1_len + chunk2_len, chunk3, chunk3_len);
                expected[total_input_len] = '\0';

                /* Decompress concatenated data */
                ret = flb_snappy_uncompress_framed_data(concatenated, concat_len,
                                                        &decompressed_data, &decompressed_len);
                TEST_CHECK(ret == 0);
                TEST_MSG("flb_snappy_uncompress_framed_data failed for concatenated chunks, ret=%d", ret);

                if (ret == 0) {
                    TEST_CHECK(decompressed_len == total_input_len);
                    TEST_MSG("Length mismatch for concatenated: expected %zu, got %zu",
                             total_input_len, decompressed_len);

                    ret = memcmp(expected, decompressed_data, total_input_len);
                    TEST_CHECK(ret == 0);
                    TEST_MSG("Content mismatch for concatenated chunks");

                    flb_free(decompressed_data);
                }
                flb_free(expected);
            }
            flb_free(concatenated);
        }
    }

    if (compressed1) flb_free(compressed1);
    if (compressed2) flb_free(compressed2);
    if (compressed3) flb_free(compressed3);

    /* Test case 4: Empty input should fail gracefully */
    ret = flb_snappy_compress_framed_data(NULL, 0, &compressed_data, &compressed_len);
    TEST_CHECK(ret == -1);
    TEST_MSG("Expected failure for NULL/empty input, got ret=%d", ret);
}

void test_b64_truncated_gzip()
{
struct flb_aws_test_case cases[] =
    {
        {
            "gzip",
            "hello hello hello hello hello hello",
            "hello hello hello hello hello hello", /* Auto decoded via gzip */
            0 /* Expected ret */
        },
        { 0 }
    };

    flb_aws_compress_truncate_b64_test_cases__gzip_decode(cases,
        41);
}

void test_b64_truncated_zstd()
{
struct flb_aws_test_case cases[] =
    {
        {
            "zstd",
            "hello hello hello hello hello hello",
            "hello hello hello hello hello hello",
            0 /* Expected ret */
        },
        { 0 }
    };

    flb_aws_compress_truncate_b64_test_cases__zstd_decode(cases,41);
}

void test_b64_truncated_gzip_truncation()
{
struct flb_aws_test_case cases[] =
    {
        {
            "gzip",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod temp"
            "or incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, qui"
            "s nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequ"
            "at. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum do"
            "lore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proiden"
            "t, sunt in culpa qui officia deserunt mollit anim id est laborum. xyz",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod temp"
            "or incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, qui"
            "s nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequ"
            "at. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum do"
            "lore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proiden"
            "t, su[Truncated...]"
            /*"nt in culpa qui officia deserunt mollit anim id est laborum. xyz",*/
            "",
            0 /* Expected ret */
        },
        {
            "gzip",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod temp"
            "or incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, qui"
            "s nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequ"
            "at. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum do"
            "lore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proiden"
            "t, sunt in culpa qui officia deserunt mollit anim id est laborum.",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod temp"
            "or incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, qui"
            "s nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequ"
            "at. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum do"
            "lore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proiden"
            "t, sunt in culpa qui officia deserunt mollit anim id est laborum.",
            0 /* Expected ret */
        },
        { 0 }
    };

    flb_aws_compress_truncate_b64_test_cases__gzip_decode(cases,
        381);
}

void test_b64_truncated_gzip_truncation_buffer_too_small()
{
struct flb_aws_test_case cases[] =
    {
        {
            "gzip",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod temp"
            "or incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, qui"
            "s nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequ"
            "at. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum do"
            "lore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proiden"
            "t, sunt in culpa qui officia deserunt mollit anim id est laborum.",
            "",
            -1 /* Expected ret */
        },
        {
            "gzip",
            "",
            "",
            -1 /* Expected ret: Buffer too small */
        },
        { 0 }
    };

    flb_aws_compress_truncate_b64_test_cases__gzip_decode(cases,
        14);
}

void test_b64_truncated_gzip_truncation_edge()
{
struct flb_aws_test_case cases[] =
    {
        /*{
            "gzip",
            "",
            "",
            0
        }, *//* This test case fails, because GZIP can zip empty strings but not unzip */
        {
            "gzip",
            "[Truncated...]", /* Endless loop? */
            "",
            -1 /* Expected ret */
        },
        { 0 }
    };

    flb_aws_compress_truncate_b64_test_cases__gzip_decode(cases,
        51);
}

void test_b64_truncated_gzip_truncation_multi_rounds()
{
struct flb_aws_test_case cases[] =
    {
        {
            "gzip",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod temp"
            "or incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, qui"
            "s nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequ"
            "at. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum do"
            "lore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proiden"
            "t, sunt in culpa qui officia deserunt mollit anim id est laborum."
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "", /* First half of the compression is heavy, the second half is light. */
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod temp"
            "or incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, qui"
            "s nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequ"
            "at. Duis aute irure dolor in reprehenderit in voluptate velit es"
            "[Truncated...]", /* Bad estimation of resizing, 3 truncation iterations
                               * needed */
            0 /* Expected ret */
        },
        { 0 }
    };

    flb_aws_compress_truncate_b64_test_cases__gzip_decode(cases,
        300);
}

TEST_LIST = {
    { "test_compression_gzip", test_compression_gzip },
    { "test_compression_zstd", test_compression_zstd },
    { "test_compression_snappy", test_compression_snappy },
    { "test_b64_truncated_gzip", test_b64_truncated_gzip },
    { "test_b64_truncated_zstd", test_b64_truncated_zstd },
    { "test_b64_truncated_gzip_truncation", test_b64_truncated_gzip_truncation },
    { "test_b64_truncated_gzip_truncation_buffer_too_small",
      test_b64_truncated_gzip_truncation_buffer_too_small },
    { "test_b64_truncated_gzip_truncation_edge",
      test_b64_truncated_gzip_truncation_edge },
    { "test_b64_truncated_gzip_truncation_multi_rounds",
      test_b64_truncated_gzip_truncation_multi_rounds },
    { 0 }
};

/** ------ Helper Methods ------ **/

/* test case loop for flb_aws_compress */
static void flb_aws_compress_test_cases(struct flb_aws_test_case *cases)
{
    flb_aws_compress_general_test_cases(FLB_AWS_COMPRESS_TEST_TYPE_COMPRESS,
                                      cases, 0, NULL);
}

/* test case loop for flb_aws_compress */
static void flb_aws_compress_truncate_b64_test_cases__gzip_decode(
                                                        struct flb_aws_test_case *cases,
                                                        size_t max_out_len)
{
   flb_aws_compress_general_test_cases(FLB_AWS_COMPRESS_TEST_TYPE_B64_TRUNCATE,
                                      cases, max_out_len, &flb_gzip_uncompress);
}

static void flb_aws_compress_truncate_b64_test_cases__zstd_decode(
                                                        struct flb_aws_test_case *cases,
                                                        size_t max_out_len)
{
   flb_aws_compress_general_test_cases(FLB_AWS_COMPRESS_TEST_TYPE_B64_TRUNCATE,
                                      cases, max_out_len, &flb_zstd_uncompress);
}

/* General test case loop flb_aws_compress */
static void flb_aws_compress_general_test_cases(int test_type,
                                               struct flb_aws_test_case *cases,
                                               size_t max_out_len,
                                               int(*decompress)(void *in_data,
                                                               size_t in_len,
                                                               void **out_data,
                                                               size_t *out_len))
{
    int ret;
    size_t len;
    int compression_type = FLB_AWS_COMPRESS_NONE;
    unsigned char* out_data;
    size_t out_data_len;
    unsigned char* out_data_b64;
    size_t out_data_b64_len;
    struct flb_config *config;
    struct flb_aws_test_case *tcase = cases;

    config = flb_config_init();

    if (config == NULL) {
        return;
    }

    flb_config_exit(config);

    while (tcase->compression_keyword != 0) {

        size_t in_data_len = strlen(tcase->in_data);
        compression_type = flb_aws_compression_get_type(tcase->compression_keyword);

        TEST_CHECK(compression_type != -1);
        TEST_MSG("| flb_aws_get_compression_type: failed to get compression type for "
                 "keyword "
        "%s", tcase->compression_keyword);

        if (test_type == FLB_AWS_COMPRESS_TEST_TYPE_COMPRESS) {
            ret = flb_aws_compression_compress(compression_type, (void *) tcase->in_data,
                                              in_data_len, (void **) &out_data,
                                              &out_data_len);
        }
        else {
            ret = flb_aws_compression_b64_truncate_compress(compression_type, max_out_len,
                                                           (void *) tcase->in_data,
                                                           in_data_len,
                                                           (void **) &out_data,
                                                           &out_data_len);
        }

        TEST_CHECK(ret == tcase->expect_ret);
        TEST_MSG("| Expected return value: %i", tcase->expect_ret);
        TEST_MSG("| Produced return value: %i", ret);

        if (ret != 0) {
            TEST_MSG("*- For input data: %s", tcase->in_data);
            ++tcase;
            continue;
        }

        if (test_type == FLB_AWS_COMPRESS_TEST_TYPE_COMPRESS) {
            out_data_b64 = base64_encode(out_data, out_data_len, &out_data_b64_len);
            /* remove newline character which is a part of this encode algo */
            --out_data_b64_len;
            flb_free(out_data);
            out_data = NULL;
        }
        else {
            /* decode b64 so we can compare plain text */
            out_data_b64 = base64_decode(out_data, out_data_len, &out_data_b64_len);
            flb_free(out_data);
            out_data = out_data_b64;
            out_data_len = out_data_b64_len;
            ret = decompress(out_data, out_data_len, (void *)&out_data_b64,
                            &out_data_b64_len);
            flb_free(out_data);
            out_data = NULL;
            if (!TEST_CHECK(ret == 0)) {
                TEST_MSG("| Decompression failure");
                out_data_b64 = flb_malloc(1); /* placeholder malloc */
            }
        }

        ret = memcmp(tcase->expect_out_data_b64, out_data_b64, out_data_b64_len);
        TEST_CHECK(ret == 0);
        TEST_MSG("| Expected output(%s): %s",
                (test_type == FLB_AWS_COMPRESS_TEST_TYPE_COMPRESS)
                ? "b64" : "decompressed", tcase->expect_out_data_b64);
        TEST_MSG("| Produced output(%s): %s",
                (test_type == FLB_AWS_COMPRESS_TEST_TYPE_COMPRESS)
                ? "b64" : "decompressed", out_data_b64);

        len = strlen(tcase->expect_out_data_b64);
        TEST_CHECK(len == out_data_b64_len);
        TEST_MSG("| Expected length: %zu", len);
        TEST_MSG("| Produced length: %zu", out_data_b64_len);

        TEST_MSG("*- For input data: %s", tcase->in_data);

        flb_free(out_data_b64);
        ++tcase;
    }
}

/* B64 check script copied from Monkey Auth Plugin */
/* Change log:
 *      Removed auto new line entry from every 72 characters to make consistant with
 *      the actual base64 conversion
 */
/* Copied from monkey/plugins/auth/base64.c */

#define __mem_alloc    malloc
#define __mem_free     free

static const unsigned char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
static unsigned char * base64_encode(const unsigned char *src, size_t len,
			      size_t *out_len)
{
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	size_t olen;
	size_t line_len;

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 72; /* line feeds */
	olen++; /* nul termination */
	if (olen < len)
		return NULL; /* integer overflow */

	out = __mem_alloc(olen);

	if (out == NULL)
		return NULL;

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		line_len += 4;
	}

	if (line_len)
		*pos++ = '\n';

	*pos = '\0';
	if (out_len)
		*out_len = pos - out;
	return out;
}

/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
static unsigned char * base64_decode(const unsigned char *src, size_t len,
			      size_t *out_len)
{
	unsigned char dtable[256], *out, *pos, block[4], tmp;
	size_t i, count, olen;
	int pad = 0;

	memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[base64_table[i]] = (unsigned char) i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return NULL;

	olen = (count / 4 * 3) + 1;
	pos = out = __mem_alloc(olen);
	if (out == NULL)
		return NULL;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
					/* Invalid padding */
					__mem_free(out);
					return NULL;
				}
				break;
			}
		}
	}
        *pos = '\0';

	*out_len = pos - out;
	return out;
}

/* End of copied base64.c from monkey */
