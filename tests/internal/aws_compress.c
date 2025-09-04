/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_zstd.h>

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
