#include "yyjson.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if YYJSON_READER_DEPTH_LIMIT
static void make_nested_json_arrays(char *json, int depth)
{
    char *jsonp = json;
    int i;
    for (i = 0; i < depth; i++) {
        *jsonp++ = '[';
    }
    *jsonp++ = '8';
    for (i = 0; i < depth; i++) {
        *jsonp++ = ']';
    }
    *jsonp = 0;
}
static void make_nested_json_objects(char *json, int depth)
{
    char *jsonp = json;
    int i;
    for (i = 0; i < depth; i++) {
        *jsonp++ = '{';
        *jsonp++ = '"';
        *jsonp++ = 'a' + i % 26;
        *jsonp++ = '"';
        *jsonp++ = ':';
    }
    *jsonp++ = '8';
    for (i = 0; i < depth; i++) {
        *jsonp++ = '}';
    }
    *jsonp = 0;
}

static int check_parse(char *json)
{
    yyjson_read_err err;
    yyjson_doc *doc;
    printf("Parsing nested JSON, depth limit = %d\n", YYJSON_READER_DEPTH_LIMIT);
    doc = yyjson_read_opts(json, strlen(json), 0, NULL, &err);
    yyjson_doc_free(doc);
    printf("=> Error code: %d\n", err.code);
    if (err.code != YYJSON_READ_ERROR_DEPTH) {
        printf("Expected depth error, but didn't get one!\n");
        return 1;
    }
    return 0;
}
#endif

#if YYJSON_WRITER_DEPTH_LIMIT && !YYJSON_DISABLE_WRITER
static yyjson_mut_val *nested_arr(yyjson_mut_doc *doc, int depth, int empty)
{
    yyjson_mut_val *val = empty ? yyjson_mut_arr(doc) : yyjson_mut_int(doc, 1);
    int i, start = empty ? 1 : 0;
    for (i = start; i < depth; i++) {
        yyjson_mut_val *arr = yyjson_mut_arr(doc);
        yyjson_mut_arr_append(arr, val);
        val = arr;
    }
    return val;
}

static int check_write(int depth, int empty, yyjson_write_flag flg,
                       int expect_err)
{
    yyjson_mut_doc *mdoc = yyjson_mut_doc_new(NULL);
    yyjson_doc *idoc;
    yyjson_write_err err;
    char *str;
    int rc = 0;

    yyjson_mut_doc_set_root(mdoc, nested_arr(mdoc, depth, empty));
    str = yyjson_mut_write_opts(mdoc, flg, NULL, NULL, &err);
    printf("mut write depth %d empty %d pretty %d => code %d\n",
           depth, empty, (flg != 0), err.code);
    free(str);
    if (expect_err) {
        if (err.code != YYJSON_WRITE_ERROR_DEPTH) rc = 1;
    } else if (err.code != YYJSON_WRITE_SUCCESS) {
        rc = 1;
    }

    idoc = yyjson_mut_doc_imut_copy(mdoc, NULL);
    if (!idoc) {
        printf("imut copy failed\n");
        yyjson_mut_doc_free(mdoc);
        return 1;
    }
    str = yyjson_write_opts(idoc, flg, NULL, NULL, &err);
    printf("imm write depth %d empty %d pretty %d => code %d\n",
           depth, empty, (flg != 0), err.code);
    free(str);
    if (expect_err) {
        if (err.code != YYJSON_WRITE_ERROR_DEPTH) rc = 1;
    } else if (err.code != YYJSON_WRITE_SUCCESS) {
        rc = 1;
    }

    yyjson_doc_free(idoc);
    yyjson_mut_doc_free(mdoc);
    if (rc) printf("Unexpected writer result\n");
    return rc;
}
#endif

int main(void)
{
    int rc = 0;
#if YYJSON_READER_DEPTH_LIMIT
    {
        int depth = YYJSON_READER_DEPTH_LIMIT + 1;
        char *json = (char *)malloc((size_t)depth * 8 + 8);
        if (!json) return 1;
        make_nested_json_arrays(json, depth);
        rc |= check_parse(json);
        make_nested_json_objects(json, depth);
        rc |= check_parse(json);
        free(json);
    }
#endif
#if YYJSON_WRITER_DEPTH_LIMIT && !YYJSON_DISABLE_WRITER
    {
        int lim = YYJSON_WRITER_DEPTH_LIMIT;
        yyjson_write_flag pretty = YYJSON_WRITE_PRETTY;
        rc |= check_write(lim, 0, 0, 0);
        rc |= check_write(lim, 0, pretty, 0);
        rc |= check_write(lim + 1, 0, 0, 1);
        rc |= check_write(lim + 1, 0, pretty, 1);
        rc |= check_write(lim, 1, 0, 0);
        rc |= check_write(lim, 1, pretty, 0);
        rc |= check_write(lim + 1, 1, 0, 1);
        rc |= check_write(lim + 1, 1, pretty, 1);
    }
#endif
#if !YYJSON_READER_DEPTH_LIMIT && !YYJSON_WRITER_DEPTH_LIMIT
    printf("Library not compiled with depth limit support.\n");
#endif
    return rc;
}
