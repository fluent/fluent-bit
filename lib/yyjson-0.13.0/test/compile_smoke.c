/* Smoke test for old compilers and environments without CMake support */

#include "yyjson.h"

#define SMOKE_BUF_SIZE ((size_t)32 * 1024)
static unsigned char smoke_buf[SMOKE_BUF_SIZE];
static yyjson_alc smoke_alc;

#if YYJSON_FREESTANDING
#define yy_assert(expr) do { \
    if (!(expr)) return 1; \
} while (0)
#else
#define yy_assert(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "Assertion failed: %s (%s:%d)\n", \
                #expr, __FILE__, __LINE__); \
        abort(); \
    } \
} while (0)
#endif

static int str_eq(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    return la == lb && memcmp(a, b, la) == 0;
}

static int test_read(void) {
    const char *json = "{\"str\":\"Harry\",\"fp\":0.5,\"arr\":[42,-42,null]}";
    yyjson_doc *doc;
    yyjson_val *root, *arr;
    char *out;

    doc = yyjson_read_opts((char *)(void *)json, strlen(json), 0, &smoke_alc, NULL);
    yy_assert(doc != NULL);
    
    root = yyjson_doc_get_root(doc);
    yy_assert(yyjson_is_str(yyjson_obj_get(root, "str")));
    yy_assert(yyjson_equals_str(yyjson_obj_get(root, "str"), "Harry"));
    yy_assert(yyjson_is_real(yyjson_obj_get(root, "fp")));
    yy_assert(yyjson_get_real(yyjson_obj_get(root, "fp")) == 0.5);
    
    arr = yyjson_obj_get(root, "arr");
    yy_assert(yyjson_is_arr(arr) && yyjson_arr_size(arr) == 3);
    yy_assert(yyjson_get_int(yyjson_arr_get(arr, 0)) == 42);
    yy_assert(yyjson_get_int(yyjson_arr_get(arr, 1)) == -42);
    yy_assert(yyjson_is_null(yyjson_arr_get(arr, 2)));
    
    out = yyjson_write_opts(doc, 0, &smoke_alc, NULL, NULL);
    yy_assert(out != NULL);
    yy_assert(str_eq(json, out));
    smoke_alc.free(smoke_alc.ctx, out);
    
    yyjson_doc_free(doc);
    return 0;
}

static int test_write(void) {
    const char *json = "{\"str\":\"Harry\",\"fp\":0.5,\"arr\":[42,-42,null]}";
    yyjson_mut_doc *doc;
    yyjson_mut_val *root, *arr;
    char *out;

    doc = yyjson_mut_doc_new(&smoke_alc);
    yy_assert(doc != NULL);

    root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "str", "Harry");
    yyjson_mut_obj_add_real(doc, root, "fp", 0.5);

    arr = yyjson_mut_arr(doc);
    yyjson_mut_obj_add(root, yyjson_mut_str(doc, "arr"), arr);
    yyjson_mut_arr_add_int(doc, arr, 42);
    yyjson_mut_arr_add_int(doc, arr, -42);
    yyjson_mut_arr_add_null(doc, arr);

    out = yyjson_mut_write_opts(doc, 0, &smoke_alc, NULL, NULL);
    yy_assert(out != NULL);
    yy_assert(str_eq(out, json));
    smoke_alc.free(smoke_alc.ctx, out);
    
    yyjson_mut_doc_free(doc);
    return 0;
}

int main(void) {
#if !YYJSON_FREESTANDING && !YYJSON_DISABLE_FILE
    printf("yyjson %s smoke test...\n", YYJSON_VERSION_STRING);
#endif

    yyjson_alc_pool_init(&smoke_alc, smoke_buf, sizeof(smoke_buf));
    if (test_read()) return 1;
    if (test_write()) return 1;

#if !YYJSON_FREESTANDING && !YYJSON_DISABLE_FILE
    printf("All smoke tests passed\n");
#endif

    return 0;
}
