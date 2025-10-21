// This file is used to test the functionality of JSON reader.

#include "yyjson.h"
#include "yy_test_utils.h"

#if !YYJSON_DISABLE_READER



// Expect result
typedef enum {
    EXPECT_NONE,
    EXPECT_PASS,
    EXPECT_FAIL,
} expect_type;

// All feature flags
static const yyjson_read_flag ALL_FLAGS[] = {
    1 << 1, // YYJSON_READ_STOP_WHEN_DONE
    1 << 7, // YYJSON_READ_BIGNUM_AS_RAW
    1 << 5, // YYJSON_READ_NUMBER_AS_RAW
    1 << 2, // YYJSON_READ_ALLOW_TRAILING_COMMAS
    1 << 3, // YYJSON_READ_ALLOW_COMMENTS
    1 << 4, // YYJSON_READ_ALLOW_INF_AND_NAN
    1 << 6, // YYJSON_READ_ALLOW_INVALID_UNICODE
    1 << 8, // YYJSON_READ_ALLOW_BOM
    1 << 9, // YYJSON_READ_ALLOW_EXT_NUMBER
    1 << 10, // YYJSON_READ_ALLOW_EXT_ESCAPE
    1 << 11, // YYJSON_READ_ALLOW_EXT_WHITESPACE
    1 << 12, // YYJSON_READ_ALLOW_SINGLE_QUOTED_STR
    1 << 13, // YYJSON_READ_ALLOW_UNQUOTED_KEY
};



/*==============================================================================
 * MARK: - Helper
 *============================================================================*/

static void test_read_data(const char *path, char *dat, usize len,
                           yyjson_read_flag flg, expect_type expect) {
#if YYJSON_DISABLE_UTF8_VALIDATION
    bool is_utf8 = yy_str_is_utf8(dat, len);
    if (!is_utf8) return;
#endif

    // test read
    yyjson_read_err err;
    yyjson_doc *doc = yyjson_read_opts(dat, len, flg, NULL, &err);
    if (expect == EXPECT_PASS) {
        yy_assertf(doc != NULL, "should pass but fail (0x%X): %s", flg, path);
        yy_assert(yyjson_doc_get_read_size(doc) > 0);
        yy_assert(yyjson_doc_get_val_count(doc) > 0);
        yy_assert(err.code == YYJSON_READ_SUCCESS);
        yy_assert(err.msg == NULL);
    }
    if (expect == EXPECT_FAIL) {
        yy_assertf(doc == NULL, "should fail but pass (0x%X): %s", flg, path);
        yy_assert(yyjson_doc_get_read_size(doc) == 0);
        yy_assert(yyjson_doc_get_val_count(doc) == 0);
        yy_assert(err.code != YYJSON_READ_SUCCESS);
        yy_assert(err.msg != NULL);
    }
    
    // test write again
#if !YYJSON_DISABLE_WRITER
    if (doc) {
        usize ret_len;
        char *ret;
        ret = yyjson_write(doc, YYJSON_WRITE_INF_AND_NAN_AS_NULL, &ret_len);
        yy_assert(ret && ret_len);
        free(ret);
        ret = yyjson_write(doc, YYJSON_WRITE_INF_AND_NAN_AS_NULL | YYJSON_WRITE_PRETTY, &ret_len);
        yy_assert(ret && ret_len);
        free(ret);
    }
#endif
    yyjson_doc_free(doc);
    
    
    // test read insitu
    flg |= YYJSON_READ_INSITU;
    
    char *dat_cpy = malloc(len + YYJSON_PADDING_SIZE);
    yy_assert(dat_cpy);
    memcpy(dat_cpy, dat, len);
    memset(dat_cpy + len, 0, YYJSON_PADDING_SIZE);
    
    usize max_mem_len = yyjson_read_max_memory_usage(len, flg);
    void *buf = malloc(max_mem_len);
    yyjson_alc alc;
    yyjson_alc_pool_init(&alc, buf, max_mem_len);
    
    doc = yyjson_read_opts(dat_cpy, len, flg, &alc, &err);
    if (expect == EXPECT_PASS) {
        yy_assertf(doc != NULL, "should pass but fail (0x%X): %s", flg, path);
        yy_assert(yyjson_doc_get_read_size(doc) > 0);
        yy_assert(yyjson_doc_get_val_count(doc) > 0);
        yy_assert(err.code == YYJSON_READ_SUCCESS);
        yy_assert(err.msg == NULL);
    }
    if (expect == EXPECT_FAIL) {
        yy_assertf(doc == NULL, "should fail but pass (0x%X): %s", flg, path);
        yy_assert(yyjson_doc_get_read_size(doc) == 0);
        yy_assert(yyjson_doc_get_val_count(doc) == 0);
        yy_assert(err.code != YYJSON_READ_SUCCESS);
        yy_assert(err.msg != NULL);
    }
    yyjson_doc_free(doc);
    free(buf);
    free(dat_cpy);


    // test incremental read
#if !YYJSON_DISABLE_INCR_READER
    // incremental read only support standard JSON
    yyjson_read_flag non_std_flg =
        YYJSON_READ_JSON5 |
        YYJSON_READ_ALLOW_BOM |
        YYJSON_READ_ALLOW_INVALID_UNICODE;
    if (flg & non_std_flg) return;
    
    // extend input length in chunks of one byte at a time
    const size_t chunk_len = 1;
    size_t read_len = 0;
    flg &= ~YYJSON_READ_INSITU;
    
    dat_cpy = malloc(len + YYJSON_PADDING_SIZE);
    yy_assert(dat_cpy);
    memcpy(dat_cpy, dat, len);
    memset(dat_cpy + len, 0, YYJSON_PADDING_SIZE);
    
    yyjson_incr_state *state = NULL;
restart_incr_read:
    state = yyjson_incr_new((char *)dat, len, flg, NULL);
    yy_assert(state != NULL);
    yy_assert(!yyjson_incr_read(NULL, read_len, &err));
    yy_assert(!yyjson_incr_read(state, 0, &err));
    yy_assert(!yyjson_incr_read(state, 0, NULL));
    yy_assert(!yyjson_incr_read(state, len + 1, NULL));
    
    while (read_len < len || len == 0) {
        read_len += chunk_len;
        if (read_len > len) {
            read_len = len;
        }
        doc = yyjson_incr_read(state, read_len, &err);
        if (doc != NULL && read_len < len) {
            /* Incremental parsing is complete but there is more data to parse.
               This can happen when we are parsing a number on the root level
               and not all digits have been provided to the parser yet.

               Discard incremental state and restart parsing. */
            yyjson_doc_free(doc);
            yyjson_incr_free(state);
            goto restart_incr_read;
        }
        if (doc != NULL || err.code != YYJSON_READ_ERROR_MORE) {
            break;
        }
    }
    if (doc) { // test write again
#if !YYJSON_DISABLE_WRITER
        char *ret = yyjson_write(doc, 0, NULL);
        yy_assert(ret);
        free(ret);
#endif
    }
    if (expect == EXPECT_PASS) {
        yy_assertf(doc != NULL, "should pass but fail (0x%X): %s", flg, path);
        yy_assert(yyjson_doc_get_read_size(doc) > 0);
        yy_assert(yyjson_doc_get_val_count(doc) > 0);
        yy_assert(err.code == YYJSON_READ_SUCCESS);
        yy_assert(err.msg == NULL);
    }
    if (expect == EXPECT_FAIL) {
        yy_assertf(doc == NULL, "should fail but pass (0x%X): %s", flg, path);
        yy_assert(yyjson_doc_get_read_size(doc) == 0);
        yy_assert(yyjson_doc_get_val_count(doc) == 0);
        yy_assert(err.code != YYJSON_READ_SUCCESS);
        yy_assert(err.msg != NULL);
    }
    yyjson_incr_free(state);
    yyjson_doc_free(doc);
    free(dat_cpy);
#endif
}

static void test_read_file(const char *path, yyjson_read_flag flg, expect_type expect) {
    u8 *dat;
    usize len;
    yy_assertf(yy_file_read(path, &dat, &len), "fail to read file: %s", path);
    test_read_data(path, (char *)dat, len, flg, expect);
    free(dat);
}



/*==============================================================================
 * MARK: - Datasets
 *============================================================================*/

// yyjson test data
static void test_json_yyjson(void) {
    // read dir
    char dir[YY_MAX_PATH];
    yy_path_combine(dir, YYJSON_TEST_DATA_PATH, "data", "json", "test_yyjson", NULL);
    int count;
    char **names = yy_dir_read(dir, &count);
    yy_assertf(names != NULL && count != 0, "read dir fail:%s\n", dir);

    for (int i = 0; i < count; i++) {
        // read file
        char *name = names[i];
        if (name[0] == '.') continue;
        char path[YY_MAX_PATH];
        yy_path_combine(path, dir, name, NULL);
        u8 *dat;
        usize len;
        yy_assertf(yy_file_read(path, &dat, &len), "fail to read file: %s", path);
        
        // check file name
        bool has_fail       = yy_str_contains(name, "(fail)");
        bool has_garbage    = yy_str_contains(name, "(garbage)");
        bool has_bignum     = yy_str_contains(name, "(bignum)");
        bool has_bighex     = yy_str_contains(name, "(bighex)");
        bool has_comma      = yy_str_contains(name, "(comma)");
        bool has_comment    = yy_str_contains(name, "(comment)");
        bool has_endcomment = yy_str_contains(name, "(endcomment)");
        bool has_inf        = yy_str_contains(name, "(inf)");
        bool has_nan        = yy_str_contains(name, "(nan)");
        bool has_str_err    = yy_str_contains(name, "(str_err)");
        bool has_bom        = yy_str_contains(name, "(bom)");
        bool has_ext_num    = yy_str_contains(name, "(ext_num)");
        bool has_ext_esc    = yy_str_contains(name, "(ext_esc)");
        bool has_ext_ws     = yy_str_contains(name, "(ext_ws)");
        bool has_str_sq     = yy_str_contains(name, "(str_sq)");
        bool has_str_uq     = yy_str_contains(name, "(str_uq)");
        bool has_non_std = (has_bighex | has_comma | has_comment |
                            has_inf | has_nan | has_str_err | has_bom |
                            has_ext_num | has_ext_esc |
                            has_ext_ws | has_str_sq | has_str_uq);
        
        // test all flag combination
        u32 flg_num = (u32)yy_nelems(ALL_FLAGS);
        u32 flg_comb_num = 1 << flg_num;
        for (u32 c = 0; c < flg_comb_num; c++) {
            yyjson_write_flag flg = 0;
            for (u32 f = 0; f < flg_num; f++) {
                if (c & (1 << f)) flg |= ALL_FLAGS[f];
            }
            
            // check if the current combined flag is valid
            bool pass = !has_fail;
            pass &= !has_garbage    || (flg & (YYJSON_READ_STOP_WHEN_DONE));
            pass &= !has_bignum     || (flg & (YYJSON_READ_BIGNUM_AS_RAW |
                                               YYJSON_READ_NUMBER_AS_RAW |
                                               YYJSON_READ_ALLOW_INF_AND_NAN));
            pass &= !has_bighex     || (flg & (YYJSON_READ_BIGNUM_AS_RAW |
                                               YYJSON_READ_NUMBER_AS_RAW));
            pass &= !has_comma      || (flg & (YYJSON_READ_ALLOW_TRAILING_COMMAS));
            pass &= !has_comment    || (flg & (YYJSON_READ_ALLOW_COMMENTS));
            pass &= !has_endcomment || (flg & (YYJSON_READ_ALLOW_COMMENTS |
                                               YYJSON_READ_STOP_WHEN_DONE));
            pass &= !has_inf        || (flg & (YYJSON_READ_ALLOW_INF_AND_NAN));
            pass &= !has_nan        || (flg & (YYJSON_READ_ALLOW_INF_AND_NAN));
            pass &= !has_str_err    || (flg & (YYJSON_READ_ALLOW_INVALID_UNICODE));
            pass &= !has_bom        || (flg & (YYJSON_READ_ALLOW_BOM |
                                               YYJSON_READ_ALLOW_EXT_WHITESPACE));
            pass &= !has_ext_num    || (flg & (YYJSON_READ_ALLOW_EXT_NUMBER));
            pass &= !has_ext_esc    || (flg & (YYJSON_READ_ALLOW_EXT_ESCAPE));
            pass &= !has_ext_ws     || (flg & (YYJSON_READ_ALLOW_EXT_WHITESPACE));
            pass &= !has_str_sq     || (flg & (YYJSON_READ_ALLOW_SINGLE_QUOTED_STR));
            pass &= !has_str_uq     || (flg & (YYJSON_READ_ALLOW_UNQUOTED_KEY));
#if YYJSON_DISABLE_NON_STANDARD
            pass &= !has_non_std;
            pass &= !has_bignum     || (flg & (YYJSON_READ_BIGNUM_AS_RAW |
                                               YYJSON_READ_NUMBER_AS_RAW));
            pass &= !has_endcomment || (flg & YYJSON_READ_STOP_WHEN_DONE);
#endif
            test_read_data(path, (char *)dat, len, flg, pass ? EXPECT_PASS : EXPECT_FAIL);
        }
        
        // free file data
        free(dat);
    }
    yy_dir_free(names);
    
    
    // test invalid input
    yy_assert(!yyjson_read_opts(NULL, 0, 0, NULL, NULL));
    yy_assert(!yyjson_read_opts("1", 0, 0, NULL, NULL));
    yy_assert(!yyjson_read_opts("1", SIZE_MAX, 0, NULL, NULL));
    
    // test read file
    yy_path_combine(dir, YYJSON_TEST_DATA_PATH, "data", "json", "test_yyjson", "blns.json", NULL);
    yyjson_doc *doc = yyjson_read_file(dir, 0, NULL, NULL);
    yy_assert(yyjson_is_arr(yyjson_doc_get_root(doc)));
    yyjson_doc_free(doc);
    
    // test read file fail
    yyjson_read_err err;
    yy_assert(!yyjson_read_file(NULL, 0, NULL, NULL));
    yy_assert(!yyjson_read_file("...not a valid file...", 0, NULL, &err));
    yy_assert(err.code == YYJSON_READ_ERROR_FILE_OPEN);
    
    // test alloc fail
    yyjson_alc alc_small;
    char alc_buf[64];
    yy_assert(yyjson_alc_pool_init(&alc_small, alc_buf, sizeof(void *) * 8));
    yy_assert(!yyjson_read_opts("[]", 2, 0, &alc_small, NULL));
    yy_assert(!yyjson_read_opts("[  ]", 4, 0, &alc_small, NULL));
    yy_assert(!yyjson_read_opts("123", 3, 0, &alc_small, NULL));
    yy_assert(!yyjson_read_file(dir, 0, &alc_small, NULL));
}



// http://www.json.org/JSON_checker/
static void test_json_checker(void) {
    char dir[YY_MAX_PATH];
    yy_path_combine(dir, YYJSON_TEST_DATA_PATH, "data", "json", "test_checker", NULL);
    int count;
    char **names = yy_dir_read(dir, &count);
    yy_assertf(names != NULL && count != 0, "read dir fail:%s\n", dir);
    
    for (int i = 0; i < count; i++) {
        char *name = names[i];
        char path[YY_MAX_PATH];
        yy_path_combine(path, dir, name, NULL);
        if (yy_str_has_prefix(name, "pass_")) {
            test_read_file(path, 0, EXPECT_PASS);
        } else if (yy_str_has_prefix(name, "fail_") &&
                   !yy_str_contains(name, "EXCLUDE")) {
            test_read_file(path, 0, EXPECT_FAIL);
        } else {
            test_read_file(path, 0, EXPECT_NONE);
        }
    }
    
    yy_dir_free(names);
}

// https://github.com/nst/JSONTestSuite
static void test_json_parsing(void) {
    char dir[YY_MAX_PATH];
    yy_path_combine(dir, YYJSON_TEST_DATA_PATH, "data", "json", "test_parsing", NULL);
    int count;
    char **names = yy_dir_read(dir, &count);
    yy_assertf(names != NULL && count != 0, "read dir fail:%s\n", dir);
    
    for (int i = 0; i < count; i++) {
        char *name = names[i];
        if (*name == '.') continue;
        char path[YY_MAX_PATH];
        yy_path_combine(path, dir, name, NULL);
        
        if (yy_str_has_prefix(name, "y_")) {
            test_read_file(path, 0, EXPECT_PASS);
        } else if (yy_str_has_prefix(name, "n_")) {
            test_read_file(path, 0, EXPECT_FAIL);
        } else {
            test_read_file(path, 0, EXPECT_NONE);
        }
    }
    yy_dir_free(names);
}

// https://github.com/nst/JSONTestSuite
static void test_json_transform(void) {
    char dir[YY_MAX_PATH];
    yy_path_combine(dir, YYJSON_TEST_DATA_PATH, "data", "json", "test_transform", NULL);
    int count;
    char **names = yy_dir_read(dir, &count);
    yy_assertf(names != NULL && count != 0, "read dir fail:%s\n", dir);
    
    for (int i = 0; i < count; i++) {
        char *name = names[i];
        if (*name == '.') continue;
        char path[YY_MAX_PATH];
        yy_path_combine(path, dir, name, NULL);
        
        if (yy_str_contains(name, "invalid")) {
            test_read_file(path, 0, EXPECT_FAIL);
        } else {
            test_read_file(path, 0, EXPECT_PASS);
        }
    }
    
    yy_dir_free(names);
}

// https://github.com/miloyip/nativejson-benchmark
static void test_json_encoding(void) {
    char dir[YY_MAX_PATH];
    yy_path_combine(dir, YYJSON_TEST_DATA_PATH, "data", "json", "test_encoding", NULL);
    int count;
    char **names = yy_dir_read(dir, &count);
    yy_assertf(names != NULL && count != 0, "read dir fail:%s\n", dir);
    
    for (int i = 0; i < count; i++) {
        char *name = names[i];
        if (*name == '.') continue;
        char path[YY_MAX_PATH];
        yy_path_combine(path, dir, name, NULL);
        
        if (strcmp(name, "utf8.json") == 0) {
            test_read_file(path, 0, EXPECT_PASS);
        } else if (strcmp(name, "utf8bom.json") == 0) {
            test_read_file(path, 0, EXPECT_FAIL);
#if !YYJSON_DISABLE_NON_STANDARD
            test_read_file(path, YYJSON_READ_ALLOW_BOM, EXPECT_PASS);
            test_read_file(path, YYJSON_READ_ALLOW_EXT_WHITESPACE, EXPECT_PASS);
#else
            test_read_file(path, YYJSON_READ_ALLOW_BOM, EXPECT_FAIL);
            test_read_file(path, YYJSON_READ_ALLOW_EXT_WHITESPACE, EXPECT_FAIL);
#endif
        } else {
            test_read_file(path, 0, EXPECT_FAIL);
            test_read_file(path, YYJSON_READ_ALLOW_BOM, EXPECT_FAIL);
            test_read_file(path, YYJSON_READ_ALLOW_EXT_WHITESPACE, EXPECT_FAIL);
        }
    }
    yy_dir_free(names);
}



/*==============================================================================
 * MARK: - Whitespace
 *============================================================================*/

/// Validate `read(src, flg) == read(dst)`.
static void validate_whitespace(const char *src, const char *dst, yyjson_read_flag flg) {
    yyjson_doc *doc_src = yyjson_read(src, src ? strlen(src) : 0, flg);
    yyjson_doc *doc_dst = yyjson_read(dst, dst ? strlen(dst) : 0, 0);

#if !YYJSON_DISABLE_NON_STANDARD
    if (doc_dst) {
        yy_assert(doc_src);
        yy_assert(yyjson_equals(yyjson_doc_get_root(doc_src), yyjson_doc_get_root(doc_dst)));
    } else {
        yy_assert(!doc_src);
    }
#endif
    
    yyjson_doc_free(doc_src);
    yyjson_doc_free(doc_dst);
}

static void test_json_whitespace(void) {
    // ---------------------------------
    // standard whitespace
    validate_whitespace
    (
     "[1, 2]",
     "[1,2]", 0);
    validate_whitespace
    (
     "[1, 2]",
     "[1,2]", YYJSON_READ_ALLOW_EXT_WHITESPACE);
    
    validate_whitespace
    (
     "[1,\n2]",
     "[1,2]", 0);
    validate_whitespace
    (
     "[1,\n2]",
     "[1,2]", YYJSON_READ_ALLOW_EXT_WHITESPACE);
    
    
    // ---------------------------------
    // single-byte whitespace
    validate_whitespace
    (
     "[1,\v2]",
     NULL, 0);
    validate_whitespace
    (
     "[1,\v2]",
     "[1,2]", YYJSON_READ_ALLOW_EXT_WHITESPACE);
    validate_whitespace
    (
     "[1,\f2]",
     NULL, 0);
    validate_whitespace
    (
     "[1,\f2]",
     "[1,2]", YYJSON_READ_ALLOW_EXT_WHITESPACE);
    
    
    // ---------------------------------
    // multe-byte whitespace
    validate_whitespace
    (
     "[1, \xC2\xA0 2]",
     NULL, 0);
    validate_whitespace
    (
     "[1, \xC2\xA0 2]",
     "[1,2]", YYJSON_READ_ALLOW_EXT_WHITESPACE);
    validate_whitespace
    (
     "[1, \xE1\x9A\x80\xE2\x80\x80\xE2\x80\x81\xE2\x80\x8A 2]",
     NULL, 0);
    validate_whitespace
    (
     "[1, \xE1\x9A\x80\xE2\x80\x80\xE2\x80\x81\xE2\x80\x8A 2]",
     "[1,2]", YYJSON_READ_ALLOW_EXT_WHITESPACE);
    validate_whitespace
    (
     "[1, \xE2\x80\x8A\xE2\x80\xA8\xE2\x80\xA9\xE2\x80\xAF 2]",
     NULL, 0);
    validate_whitespace
    (
     "[1, \xE2\x80\x8A\xE2\x80\xA8\xE2\x80\xA9\xE2\x80\xAF 2]",
     "[1,2]", YYJSON_READ_ALLOW_EXT_WHITESPACE);
    validate_whitespace
    (
     "[1, \xE2\x81\x9F\xE3\x80\x80 2]",
     NULL, 0);
    validate_whitespace
    (
     "[1, \xE2\x81\x9F\xE3\x80\x80 2]",
     "[1,2]", YYJSON_READ_ALLOW_EXT_WHITESPACE);
    
    
    // ---------------------------------
    // BOM head
    validate_whitespace
    (
     "\xEF\xBB\xBF[1,2]",
     NULL, 0);
    validate_whitespace
    (
     "\xEF\xBB\xBF[1,2]",
     "[1,2]", YYJSON_READ_ALLOW_BOM);
    validate_whitespace
    (
     "\xEF\xBB\xBF[1,2]",
     "[1,2]", YYJSON_READ_ALLOW_EXT_WHITESPACE);
    validate_whitespace
    (
     "\xEF\xBB\xBF[1,2]",
     "[1,2]", YYJSON_READ_ALLOW_BOM | YYJSON_READ_ALLOW_EXT_WHITESPACE);
    
    
    // ---------------------------------
    // BOM inside
    validate_whitespace
    (
     "[1,2\xEF\xBB\xBF]",
     NULL, 0);
    validate_whitespace
    (
     "[1,2\xEF\xBB\xBF]",
     NULL, YYJSON_READ_ALLOW_BOM);
    validate_whitespace
    (
     "[1,2\xEF\xBB\xBF]",
     "[1,2]", YYJSON_READ_ALLOW_EXT_WHITESPACE);
    validate_whitespace
    (
     "[1,2\xEF\xBB\xBF]",
     "[1,2]", YYJSON_READ_ALLOW_BOM | YYJSON_READ_ALLOW_EXT_WHITESPACE);
    
    
    // ---------------------------------
    // single-line comment
    validate_whitespace
    (
     "[1,//test\n 2]",
     "[1,2]", YYJSON_READ_ALLOW_COMMENTS);
    validate_whitespace
    (
     "[1,//test\n 2]",
     "[1,2]", YYJSON_READ_ALLOW_COMMENTS | YYJSON_READ_ALLOW_EXT_WHITESPACE);
    
    validate_whitespace
    (
     "[1,//test\xE2\x80\xA8 2]",
     NULL, YYJSON_READ_ALLOW_COMMENTS);
    validate_whitespace
    (
     "[1,//test\xE2\x80\xA8 2]",
     "[1,2]", YYJSON_READ_ALLOW_COMMENTS | YYJSON_READ_ALLOW_EXT_WHITESPACE);
    
    validate_whitespace
    (
     "[1,//test\xE2\x80\xA9 2]",
     NULL, YYJSON_READ_ALLOW_COMMENTS);
    validate_whitespace
    (
     "[1,//test\xE2\x80\xA9 2]",
     "[1,2]", YYJSON_READ_ALLOW_COMMENTS | YYJSON_READ_ALLOW_EXT_WHITESPACE);
    
    validate_whitespace
    (
     "[1,//test\xE2\x80\xAF 2]",
     NULL, YYJSON_READ_ALLOW_COMMENTS);
    validate_whitespace
    (
     "[1,//test\xE2\x80\xAF 2]",
     NULL, YYJSON_READ_ALLOW_COMMENTS | YYJSON_READ_ALLOW_EXT_WHITESPACE);
    
}



/*==============================================================================
 * MARK: - Incremental
 *============================================================================*/

#if !YYJSON_DISABLE_INCR_READER

static yyjson_doc *test_incr_read_insitu(char *dat, usize len, usize chunk_len, yyjson_read_flag flg) {
#if YYJSON_DISABLE_UTF8_VALIDATION
    if (!yy_str_is_utf8(dat, len)) return NULL;
#endif

    yyjson_read_err err;
    yyjson_incr_state *state = yyjson_incr_new(dat, len, flg, NULL);
    size_t read_len = 0;
    yyjson_doc *doc = NULL;
    while (read_len < len) {
        read_len += chunk_len;
        if (read_len > len) {
            read_len = len;
        }
        /* put some garbage where the parser is supposed to stop */
        u8 saved_end = dat[read_len];
        dat[read_len] = 'X';
        doc = yyjson_incr_read(state, read_len, &err);
        dat[read_len] = saved_end;
        if (doc != NULL || err.code != YYJSON_READ_ERROR_MORE) {
            break;
        }
    }
    if (doc != NULL) {
        yy_assert(yyjson_doc_get_read_size(doc) > 0);
        yy_assert(yyjson_doc_get_val_count(doc) > 0);
        yy_assert(err.code == YYJSON_READ_SUCCESS);
        yy_assert(err.msg == NULL);
    } else {
        yy_assert(yyjson_doc_get_read_size(doc) == 0);
        yy_assert(yyjson_doc_get_val_count(doc) == 0);
        yy_assert(err.code != YYJSON_READ_SUCCESS);
        yy_assert(err.msg != NULL);
    }
    yy_assert(err.code != YYJSON_READ_ERROR_MORE);
    yyjson_incr_free(state);
    return doc;
}

/** Returns an allocated minified JSON string representation of an object with
    obj_len keys. The values are arrays of length arr_len. The elements in the
    arrays are strings, booleans, nulls, numbers, empty arrays and empty
    objects. The returned string is padded with four null bytes. */
static char *create_json(usize obj_len, usize arr_len) {
    yy_buf buf;
    char *values[] = {"12.5", "45", "\"hello\"", "false",
                      "null", "{}", "[]", "\"\\u066Dhey\\\"\\/\""};
    usize i, j;
    if (!yy_buf_init(&buf, 1024)) return NULL;
    if (!yy_buf_append(&buf, (u8 *)"{", 1)) goto error;
    for (i = 0; i < obj_len; i++) {
        char key[32];
        if (i > 0 && !yy_buf_append(&buf, (u8 *)",", 1)) goto error;
        sprintf(key, "\"key%zu\":[", i);
        if (!yy_buf_append(&buf, (u8 *)key, strlen(key))) goto error;
        for (j = 0; j < arr_len; j++) {
            char *tmp;
            if (j > 0 && !yy_buf_append(&buf, (u8 *)",", 1)) goto error;
            tmp = values[(i + j) % (sizeof(values) / sizeof(char *))];
            if (!yy_buf_append(&buf, (u8 *)tmp, strlen(tmp))) goto error;
        }
        if (!yy_buf_append(&buf, (u8 *)"]", 1)) goto error;
    }
    if (!yy_buf_append(&buf, (u8 *)"}", 1)) goto error;
    if (!yy_buf_append(&buf, (u8 *)"\0\0\0\0", 4)) goto error;
    return (char *)buf.hdr;

error:
    yy_buf_release(&buf);
    return NULL;
}

// yyjson incremental with insitu
static void test_json_incremental(void) {
    char *dat = create_json(3, 10);
    usize len = strlen(dat);
    char *dat_dup = yy_str_copy(dat);
    yyjson_doc *doc = test_incr_read_insitu(dat, len, 1, 0);
    yy_assertf(doc != NULL, "incremental read should pass but fail\n");

#if !YYJSON_DISABLE_WRITER
    usize pretty_len;
    char *pretty;
    pretty = yyjson_write(doc, YYJSON_WRITE_PRETTY, &pretty_len);
    yy_assert(pretty && pretty_len);
    yyjson_doc_free(doc);
    pretty = realloc(pretty, pretty_len + YYJSON_PADDING_SIZE); /* for insitu */
    doc = test_incr_read_insitu(pretty, pretty_len, 1, 0);
    yy_assertf(doc != NULL, "incremental read pretty should pass but fail\n");
    usize minify_len;
    char *minify;
    minify = yyjson_write(doc, YYJSON_WRITE_ESCAPE_UNICODE | YYJSON_WRITE_ESCAPE_SLASHES, &minify_len);
    free(pretty);
#if !YYJSON_DISABLE_FAST_FP_CONV
    yy_assertf(strcmp(minify, dat_dup) == 0, "roundtrip to minified JSON mismatch\n");
#endif
    free(minify);
#endif

    yyjson_doc_free(doc);
    free(dat);
    free(dat_dup);
}

#else
static void test_json_incremental() {}
#endif



/*==============================================================================
 * MARK: - Entry
 *============================================================================*/

yy_test_case(test_json_reader) {
    test_json_yyjson();
    test_json_checker();
    test_json_parsing();
    test_json_transform();
    test_json_encoding();
    test_json_whitespace();
    test_json_incremental();
}

#else
yy_test_case(test_json_reader) {}
#endif
