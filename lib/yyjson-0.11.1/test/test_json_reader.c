// This file is used to test the functionality of JSON reader.

#include "yyjson.h"
#include "yy_test_utils.h"

#if !YYJSON_DISABLE_READER

typedef enum {
    EXPECT_NONE,
    EXPECT_PASS,
    EXPECT_FAIL,
} expect_type;

typedef enum {
    FLAG_NONE       = 0 << 0,
    FLAG_COMMA      = 1 << 0,
    FLAG_COMMENT    = 1 << 1,
    FLAG_INF_NAN    = 1 << 2,
    FLAG_EXTRA      = 1 << 3,
    FLAG_NUM_RAW    = 1 << 4,
    FLAG_BOM        = 1 << 5,
    FLAG_MAX        = 1 << 6,
} flag_type;

static void test_read_file(const char *path, flag_type type, expect_type expect) {
#if YYJSON_DISABLE_UTF8_VALIDATION
    {
        u8 *dat;
        usize dat_len;
        if (yy_file_read(path, &dat, &dat_len)) {
            bool is_utf8 = yy_str_is_utf8((const char *)dat, dat_len);
            free(dat);
            if (!is_utf8) return;
        }
    }
#endif
    
    yyjson_read_flag flag = YYJSON_READ_NOFLAG;
    if (type & FLAG_COMMA) flag |= YYJSON_READ_ALLOW_TRAILING_COMMAS;
    if (type & FLAG_COMMENT) flag |= YYJSON_READ_ALLOW_COMMENTS;
    if (type & FLAG_INF_NAN) flag |= YYJSON_READ_ALLOW_INF_AND_NAN;
    if (type & FLAG_EXTRA) flag |= YYJSON_READ_STOP_WHEN_DONE;
    if (type & FLAG_NUM_RAW) flag |= YYJSON_READ_NUMBER_AS_RAW;
    if (type & FLAG_BOM) flag |= YYJSON_READ_ALLOW_BOM;
    
    // test read from file
    yyjson_read_err err;
    yyjson_doc *doc = yyjson_read_file(path, flag, NULL, &err);
    if (expect == EXPECT_PASS) {
        yy_assertf(doc != NULL, "file should pass with flag 0x%u, but fail:\n%s\n", flag, path);
        yy_assert(yyjson_doc_get_read_size(doc) > 0);
        yy_assert(yyjson_doc_get_val_count(doc) > 0);
        yy_assert(err.code == YYJSON_READ_SUCCESS);
        yy_assert(err.msg == NULL);
    }
    if (expect == EXPECT_FAIL) {
        yy_assertf(doc == NULL, "file should fail with flag 0x%u, but pass:\n%s\n", flag, path);
        yy_assert(yyjson_doc_get_read_size(doc) == 0);
        yy_assert(yyjson_doc_get_val_count(doc) == 0);
        yy_assert(err.code != YYJSON_READ_SUCCESS);
        yy_assert(err.msg != NULL);
    }
    if (doc) { // test write again
#if !YYJSON_DISABLE_WRITER
        usize len;
        char *ret;
        ret = yyjson_write(doc, YYJSON_WRITE_ALLOW_INF_AND_NAN, &len);
        yy_assert(ret && len);
        free(ret);
        ret = yyjson_write(doc, YYJSON_WRITE_PRETTY | YYJSON_WRITE_ALLOW_INF_AND_NAN, &len);
        yy_assert(ret && len);
        free(ret);
#endif
    }
    yyjson_doc_free(doc);
    
    
    // test alloc fail
    yyjson_alc alc_small;
    char alc_buf[64];
    yy_assert(yyjson_alc_pool_init(&alc_small, alc_buf, sizeof(void *) * 8));
    yy_assert(!yyjson_read_file(path, flag, &alc_small, NULL));
    
    
    // test read insitu
    flag |= YYJSON_READ_INSITU;
    
    u8 *dat;
    usize len;
    bool read_suc = yy_file_read_with_padding(path, &dat, &len, YYJSON_PADDING_SIZE);
    yy_assert(read_suc);
    
    usize max_mem_len = yyjson_read_max_memory_usage(len, flag);
    void *buf = malloc(max_mem_len);
    yyjson_alc alc;
    yyjson_alc_pool_init(&alc, buf, max_mem_len);
    
    doc = yyjson_read_opts((char *)dat, len, flag, &alc, &err);
    if (expect == EXPECT_PASS) {
        yy_assertf(doc != NULL, "file should pass but fail:\n%s\n", path);
        yy_assert(yyjson_doc_get_read_size(doc) > 0);
        yy_assert(yyjson_doc_get_val_count(doc) > 0);
        yy_assert(err.code == YYJSON_READ_SUCCESS);
        yy_assert(err.msg == NULL);
    }
    if (expect == EXPECT_FAIL) {
        yy_assertf(doc == NULL, "file should fail but pass:\n%s\n", path);
        yy_assert(yyjson_doc_get_read_size(doc) == 0);
        yy_assert(yyjson_doc_get_val_count(doc) == 0);
        yy_assert(err.code != YYJSON_READ_SUCCESS);
        yy_assert(err.msg != NULL);
    }
    yyjson_doc_free(doc);
    free(buf);
    free(dat);

#if !YYJSON_DISABLE_INCR_READER
    // test incremental read
    // extend input length in chunks of one byte at a time
    const size_t chunk_len = 1;
    size_t read_len = 0;
    flag &= ~YYJSON_READ_INSITU;
    read_suc = yy_file_read_with_padding(path, &dat, &len, YYJSON_PADDING_SIZE);
    yy_assert(read_suc);

    yyjson_incr_state *state = NULL;
restart_incr_read:
    state = yyjson_incr_new((char *)dat, len, flag, NULL);
    yy_assert(state != NULL);
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
        usize out_len;
        char *ret;
        ret = yyjson_write(doc, YYJSON_WRITE_ALLOW_INF_AND_NAN, &out_len);
        yy_assert(ret && out_len);
        free(ret);
        ret = yyjson_write(doc, YYJSON_WRITE_PRETTY | YYJSON_WRITE_ALLOW_INF_AND_NAN, &out_len);
        yy_assert(ret && out_len);
        free(ret);
#endif
    }
    if (expect == EXPECT_PASS) {
        yy_assertf(doc != NULL, "file should pass but fail:\n%s\n", path);
        yy_assert(yyjson_doc_get_read_size(doc) > 0);
        yy_assert(yyjson_doc_get_val_count(doc) > 0);
        yy_assert(err.code == YYJSON_READ_SUCCESS);
        yy_assert(err.msg == NULL);
    }
    if (expect == EXPECT_FAIL) {
        yy_assertf(doc == NULL, "file should fail but pass:\n%s\n", path);
        yy_assert(yyjson_doc_get_read_size(doc) == 0);
        yy_assert(yyjson_doc_get_val_count(doc) == 0);
        yy_assert(err.code != YYJSON_READ_SUCCESS);
        yy_assert(err.msg != NULL);
    }
    yyjson_incr_free(state);
    yyjson_doc_free(doc);
    free(dat);
#endif
}

#if !YYJSON_DISABLE_INCR_READER
static yyjson_doc *test_incr_read_insitu(char *dat, usize len, usize chunk_len, flag_type type) {
#if YYJSON_DISABLE_UTF8_VALIDATION
    if (!yy_str_is_utf8(dat, len)) return NULL;
#endif

    yyjson_read_flag flag = YYJSON_READ_INSITU;
    if (type & FLAG_COMMA) flag |= YYJSON_READ_ALLOW_TRAILING_COMMAS;
    if (type & FLAG_COMMENT) flag |= YYJSON_READ_ALLOW_COMMENTS;
    if (type & FLAG_INF_NAN) flag |= YYJSON_READ_ALLOW_INF_AND_NAN;
    if (type & FLAG_EXTRA) flag |= YYJSON_READ_STOP_WHEN_DONE;
    if (type & FLAG_NUM_RAW) flag |= YYJSON_READ_NUMBER_AS_RAW;

    yyjson_read_err err;
    yyjson_incr_state *state = yyjson_incr_new(dat, len, flag, NULL);
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
#endif

// yyjson test data
static void test_json_yyjson(void) {
    char dir[YY_MAX_PATH];
    yy_path_combine(dir, YYJSON_TEST_DATA_PATH, "data", "json", "test_yyjson", NULL);
    int count;
    char **names = yy_dir_read(dir, &count);
    yy_assertf(names != NULL && count != 0, "read dir fail:%s\n", dir);

    for (int i = 0; i < count; i++) {
        char *name = names[i];
        char path[YY_MAX_PATH];
        yy_path_combine(path, dir, name, NULL);
     
        for (flag_type type = 0; type < FLAG_MAX; type++) {
            if (yy_str_has_prefix(name, "pass_")) {
                bool should_fail = false;
                if (yy_str_contains(name, "(comma)")) {
#if !YYJSON_DISABLE_NON_STANDARD
                    should_fail |= (type & FLAG_COMMA) == 0;
#else
                    should_fail = true;
#endif
                }
                if (yy_str_contains(name, "(comment)")) {
#if !YYJSON_DISABLE_NON_STANDARD
                    should_fail |= (type & FLAG_COMMENT) == 0;
#else
                    should_fail = true;
#endif
                }
                if (yy_str_contains(name, "(inf)") || yy_str_contains(name, "(nan)")) {
#if !YYJSON_DISABLE_NON_STANDARD
                    should_fail |= (type & FLAG_INF_NAN) == 0;
#else
                    should_fail = true;
#endif
                }
                if (yy_str_contains(name, "(big)")) {
#if !YYJSON_DISABLE_NON_STANDARD
                    should_fail |= (type & (FLAG_INF_NAN | FLAG_NUM_RAW)) == 0;
#else
                    should_fail |= (type & (FLAG_NUM_RAW)) == 0;
#endif
                }
                if (yy_str_contains(name, "(extra)")) {
                    should_fail |= (type & FLAG_EXTRA) == 0;
                }
                test_read_file(path, type, should_fail ? EXPECT_FAIL : EXPECT_PASS);
            } else if (yy_str_has_prefix(name, "fail_")) {
                test_read_file(path, type, EXPECT_FAIL);
            } else {
                test_read_file(path, type, EXPECT_NONE);
            }
        }
    }
    
    // test fail
    yy_assert(!yyjson_read_opts(NULL, 0, 0, NULL, NULL));
    yy_assert(!yyjson_read_opts("1", 0, 0, NULL, NULL));
    yy_assert(!yyjson_read_opts("1", SIZE_MAX, 0, NULL, NULL));
    
    yyjson_alc alc_small;
    char alc_buf[64];
    yy_assert(yyjson_alc_pool_init(&alc_small, alc_buf, sizeof(void *) * 8));
    yy_assert(!yyjson_read_opts("", 64, 0, &alc_small, NULL));
    
    yy_assert(!yyjson_read_file(NULL, 0, NULL, NULL));
    yy_assert(!yyjson_read_file("...not a valid file...", 0, NULL, NULL));
    
    yy_dir_free(names);
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
            test_read_file(path, FLAG_NONE, EXPECT_PASS);
        } else if (yy_str_has_prefix(name, "fail_") &&
                   !yy_str_contains(name, "EXCLUDE")) {
            test_read_file(path, FLAG_NONE, EXPECT_FAIL);
        } else {
            test_read_file(path, FLAG_NONE, EXPECT_NONE);
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
            test_read_file(path, FLAG_NONE, EXPECT_PASS);
        } else if (yy_str_has_prefix(name, "n_")) {
            test_read_file(path, FLAG_NONE, EXPECT_FAIL);
        } else {
            test_read_file(path, FLAG_NONE, EXPECT_NONE);
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
            test_read_file(path, FLAG_NONE, EXPECT_FAIL);
        } else {
            test_read_file(path, FLAG_NONE, EXPECT_PASS);
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
            test_read_file(path, FLAG_NONE, EXPECT_PASS);
            test_read_file(path, FLAG_BOM, EXPECT_PASS);
        } else if (strcmp(name, "utf8bom.json") == 0) {
            test_read_file(path, FLAG_NONE, EXPECT_FAIL);
#if !YYJSON_DISABLE_NON_STANDARD
            test_read_file(path, FLAG_BOM, EXPECT_PASS);
#else
            test_read_file(path, FLAG_BOM, EXPECT_FAIL);
#endif
        } else {
            test_read_file(path, FLAG_NONE, EXPECT_FAIL);
            test_read_file(path, FLAG_BOM, EXPECT_FAIL);
        }
    }
    yy_dir_free(names);
}

#if !YYJSON_DISABLE_INCR_READER

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
    yyjson_doc *doc = test_incr_read_insitu(dat, len, 1, FLAG_NONE);
    yy_assertf(doc != NULL, "incremental read should pass but fail\n");

#if !YYJSON_DISABLE_WRITER
    usize pretty_len;
    char *pretty;
    pretty = yyjson_write(doc, YYJSON_WRITE_PRETTY, &pretty_len);
    yy_assert(pretty && pretty_len);
    yyjson_doc_free(doc);
    pretty = realloc(pretty, pretty_len + YYJSON_PADDING_SIZE); /* for insitu */
    doc = test_incr_read_insitu(pretty, pretty_len, 1, FLAG_NONE);
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

yy_test_case(test_json_reader) {
    test_json_yyjson();
    test_json_checker();
    test_json_parsing();
    test_json_transform();
    test_json_encoding();
    test_json_incremental();
}

#else
yy_test_case(test_json_reader) {}
#endif
