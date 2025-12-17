#include <fluent-bit/flb_oauth2_jwt.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_base64.h>

#include "flb_tests_internal.h"
#include <string.h>

static const char *VALID_JWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0.eyJleHAiOjE3MTAwMDAwMDAsImlzcyI6Imlzc3VlciIsImF1ZCI6ImF1ZGllbmNlIiwiYXpwIjoiY2xpZW50LTEifQ.c2ln";
static const char *INVALID_SEGMENTS = "abc.def";
static const char *BAD_BASE64 = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0#.eyJleHAiOjE3MTAwMDAwMDAsImlzcyI6Imlzc3VlciIsImF1ZCI6ImF1ZGllbmNlIiwiYXpwIjoiY2xpZW50LTEifQ.c2ln";
static const char *MISSING_KID = "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE3MTAwMDAwMDAsImlzcyI6Imlzc3VlciIsImF1ZCI6ImF1ZGllbmNlIiwiYXpwIjoiY2xpZW50LTEifQ.c2ln";
static const char *BAD_ALG = "eyJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Qta2V5In0.eyJleHAiOjE3MTAwMDAwMDAsImlzcyI6Imlzc3VlciIsImF1ZCI6ImF1ZGllbmNlIiwiYXpwIjoiY2xpZW50LTEifQ.c2ln";

static void test_valid_jwt_parses()
{
    int ret;
    struct flb_oauth2_jwt jwt;

    ret = flb_oauth2_jwt_parse(VALID_JWT, strlen(VALID_JWT), &jwt);
    TEST_CHECK(ret == FLB_OAUTH2_JWT_OK);
    TEST_CHECK(jwt.signature != NULL && jwt.signature_len > 0);
    TEST_CHECK(jwt.claims.expiration == 1710000000);
    TEST_CHECK(strcmp(jwt.claims.kid, "test-key") == 0);
    TEST_CHECK(strcmp(jwt.claims.alg, "RS256") == 0);
    TEST_CHECK(strcmp(jwt.claims.issuer, "issuer") == 0);
    TEST_CHECK(strcmp(jwt.claims.audience, "audience") == 0);
    TEST_CHECK(strcmp(jwt.claims.client_id, "client-1") == 0);
    TEST_CHECK(jwt.signing_input != NULL);

    flb_oauth2_jwt_destroy(&jwt);
}

static void test_invalid_segments()
{
    int ret;
    struct flb_oauth2_jwt jwt;

    ret = flb_oauth2_jwt_parse(INVALID_SEGMENTS, strlen(INVALID_SEGMENTS), &jwt);
    TEST_CHECK(ret == FLB_OAUTH2_JWT_ERR_SEGMENT_COUNT);
}

static void test_bad_base64()
{
    int ret;
    struct flb_oauth2_jwt jwt;

    ret = flb_oauth2_jwt_parse(BAD_BASE64, strlen(BAD_BASE64), &jwt);
    TEST_CHECK(ret == FLB_OAUTH2_JWT_ERR_BASE64_HEADER);
}

static void test_missing_kid()
{
    int ret;
    struct flb_oauth2_jwt jwt;

    ret = flb_oauth2_jwt_parse(MISSING_KID, strlen(MISSING_KID), &jwt);
    TEST_CHECK(ret == FLB_OAUTH2_JWT_ERR_MISSING_KID);
}

static void test_bad_alg()
{
    int ret;
    struct flb_oauth2_jwt jwt;

    ret = flb_oauth2_jwt_parse(BAD_ALG, strlen(BAD_ALG), &jwt);
    TEST_CHECK(ret == FLB_OAUTH2_JWT_ERR_ALG_UNSUPPORTED);
}

static void test_static_key_validation()
{
    int ret;
    struct flb_oauth2_jwt jwt;
    unsigned char *modulus_bytes = NULL;
    unsigned char *exponent_bytes = NULL;
    size_t modulus_len = 0;
    size_t exponent_len = 0;

    /* JWT signed with a known RSA key */
    const char *test_jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5IiwidHlwIjoiSldUIn0.eyJleHAiOjE3MTAwMDAwMDAsImlzcyI6InRlc3QtaXNzdWVyIiwiYXVkIjoidGVzdC1hdWRpZW5jZSIsImF6cCI6InRlc3QtY2xpZW50Iiwia2lkIjoidGVzdC1rZXkifQ.mEfwBoPjhU-CbwduDcvuw_VoI6VMZsHFmHn9MeAYZ73raB7vMyMO85KBLJp9TN95iBNiKZa5Hcd7LXdTSvjQyF5QjHoZE1W0UOuPmBRDoQfkgKKhy-azMvX8RsyLU3zvXMP2v_D4CSrUkDYmLSE_DP48buMFs84C82PONkgm_0gWWqM_KH9E0QMlddL-9iWvqGkiXk-zJC0Qfuo-G98kHJC3XQRkyjqVOxVwRKey09uGgV1JlxoWoSMIwhGQq_I3G6UmbcVYhhh9Pf60NCs6SfEJ5BLyRrxwf6C8C9kvQdgmRRovbNY-BYBrX-4FrvNPChPZRnmMRpOCNgLEhcZucA";

    /* RSA public key components (base64url encoded) */
    const char *modulus_b64url = "xrgu6hNnDaqehidqV2dotxx0zps6eYwcBpT5JLi83gYSboqesABz7ct1-F0Qtq43W2ISul0zuBMLolotvWFOOqPd6Kk_fVF3gDaHhqxdv1IQo84cznRUzpBYHhft6_JupHVhgdJBv2GuoJfvOR0q5qJkXlPgM3gNh4hQywLFRpDBtjg8hrKNAyq7pics2fjU4GEDVV8tIhP1bYsUIEt7o79u8ifdIl3ctq8PvvnElOeafabRdn-SEUuBRnGNFXwV9Iu163OqvsKp4riEs4z1oHpp2UCRDknOSfgsiFcbtx2JUiQil_wC5-5Rworlq0qAGmLela5wLd8sPy4dWL-Utw";
    const char *exponent_b64url = "AQAB";

    /* Parse the JWT */
    ret = flb_oauth2_jwt_parse(test_jwt, strlen(test_jwt), &jwt);
    TEST_CHECK(ret == FLB_OAUTH2_JWT_OK);
    TEST_CHECK(jwt.signing_input != NULL);
    TEST_CHECK(jwt.signature != NULL);
    TEST_CHECK(jwt.signature_len > 0);

    /* Decode modulus from base64url */
    {
        size_t i;
        size_t j = 0;
        size_t padding = 0;
        size_t padded_len;
        size_t clean_len = strlen(modulus_b64url);
        char *padded;

        padding = (4 - (clean_len % 4)) % 4;
        padded_len = clean_len + padding;

        padded = flb_malloc(padded_len + 1);
        TEST_CHECK(padded != NULL);

        /* Convert base64url to base64 */
        for (i = 0; i < clean_len; i++) {
            char c = modulus_b64url[i];
            if (c == '-') {
                padded[j++] = '+';
            }
            else if (c == '_') {
                padded[j++] = '/';
            }
            else {
                padded[j++] = c;
            }
        }

        /* Add padding */
        for (i = 0; i < padding; i++) {
            padded[clean_len + i] = '=';
        }
        padded[padded_len] = '\0';

        /* Decode base64 */
        ret = flb_base64_decode(NULL, 0, &modulus_len,
                               (unsigned char *) padded, padded_len);
        TEST_CHECK(ret == FLB_BASE64_ERR_BUFFER_TOO_SMALL || ret == 0);

        modulus_bytes = flb_malloc(modulus_len);
        TEST_CHECK(modulus_bytes != NULL);

        ret = flb_base64_decode(modulus_bytes, modulus_len, &modulus_len,
                               (unsigned char *) padded, padded_len);
        TEST_CHECK(ret == 0);

        flb_free(padded);
    }

    /* Decode exponent from base64url */
    {
        size_t i;
        size_t j = 0;
        size_t padding = 0;
        size_t padded_len;
        size_t clean_len = strlen(exponent_b64url);
        char *padded;

        padding = (4 - (clean_len % 4)) % 4;
        padded_len = clean_len + padding;

        padded = flb_malloc(padded_len + 1);
        TEST_CHECK(padded != NULL);

        /* Convert base64url to base64 */
        for (i = 0; i < clean_len; i++) {
            char c = exponent_b64url[i];
            if (c == '-') {
                padded[j++] = '+';
            }
            else if (c == '_') {
                padded[j++] = '/';
            }
            else {
                padded[j++] = c;
            }
        }

        /* Add padding */
        for (i = 0; i < padding; i++) {
            padded[clean_len + i] = '=';
        }
        padded[padded_len] = '\0';

        /* Decode base64 */
        ret = flb_base64_decode(NULL, 0, &exponent_len,
                               (unsigned char *) padded, padded_len);
        TEST_CHECK(ret == FLB_BASE64_ERR_BUFFER_TOO_SMALL || ret == 0);

        exponent_bytes = flb_malloc(exponent_len);
        TEST_CHECK(exponent_bytes != NULL);

        ret = flb_base64_decode(exponent_bytes, exponent_len, &exponent_len,
                               (unsigned char *) padded, padded_len);
        TEST_CHECK(ret == 0);

        flb_free(padded);
    }

    /* Verify signature using flb_crypto_verify_simple */
    ret = flb_crypto_verify_simple(FLB_CRYPTO_PADDING_PKCS1,
                                   FLB_HASH_SHA256,
                                   modulus_bytes, modulus_len,
                                   exponent_bytes, exponent_len,
                                   (unsigned char *) jwt.signing_input,
                                   flb_sds_len(jwt.signing_input),
                                   (unsigned char *) jwt.signature,
                                   jwt.signature_len);

    TEST_CHECK(ret == FLB_CRYPTO_SUCCESS);

    /* Cleanup */
    if (modulus_bytes) {
        flb_free(modulus_bytes);
    }
    if (exponent_bytes) {
        flb_free(exponent_bytes);
    }
    flb_oauth2_jwt_destroy(&jwt);
}

TEST_LIST = {
    {"valid_jwt_parses", test_valid_jwt_parses},
    {"invalid_segments", test_invalid_segments},
    {"bad_base64", test_bad_base64},
    {"missing_kid", test_missing_kid},
    {"bad_alg", test_bad_alg},
    {"static_key_validation", test_static_key_validation},
    {0}
};
