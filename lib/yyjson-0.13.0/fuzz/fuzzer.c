#include <stdlib.h>
#include <string.h>
#include <yyjson.h>

/* Fuzzer-only allocator cap (not a library limit).
   OSS-Fuzz kills processes above ~2560MB RSS. Valid deep nesting with
   pretty-print can expand hugely; return NULL before the process is killed. */
#ifndef YYJSON_FUZZ_ALLOC_LIMIT
#   define YYJSON_FUZZ_ALLOC_LIMIT (512u * 1024u * 1024u)
#endif

static void *fuzz_malloc(void *ctx, size_t size) {
    (void)ctx;
    if (size > YYJSON_FUZZ_ALLOC_LIMIT) return NULL;
    return malloc(size);
}

static void *fuzz_realloc(void *ctx, void *ptr, size_t old_size, size_t size) {
    (void)ctx;
    (void)old_size;
    if (size > YYJSON_FUZZ_ALLOC_LIMIT) return NULL;
    return realloc(ptr, size);
}

static void fuzz_free(void *ctx, void *ptr) {
    (void)ctx;
    free(ptr);
}

static const yyjson_alc FUZZ_ALC = {
    fuzz_malloc, fuzz_realloc, fuzz_free, NULL
};

/*----------------------------------------------------------------------------*/

static void test_with_flags(const uint8_t *data, size_t size,
                            yyjson_read_flag rflg, yyjson_write_flag wflg) {
    yyjson_doc *idoc = yyjson_read_opts((char *)data, size, rflg, &FUZZ_ALC, NULL);
    yyjson_mut_doc *mdoc = yyjson_doc_mut_copy(idoc, &FUZZ_ALC);
    char *ijson = yyjson_write_opts(idoc, wflg, &FUZZ_ALC, NULL, NULL);
    if (ijson) FUZZ_ALC.free(FUZZ_ALC.ctx, ijson);
    char *mjson = yyjson_mut_write_opts(mdoc, wflg, &FUZZ_ALC, NULL, NULL);
    if (mjson) FUZZ_ALC.free(FUZZ_ALC.ctx, mjson);
    yyjson_doc_free(idoc);
    yyjson_mut_doc_free(mdoc);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    test_with_flags(data, size,
                    YYJSON_READ_NOFLAG,
                    YYJSON_WRITE_NOFLAG);
    test_with_flags(data, size,
                    YYJSON_READ_JSON5,
                    YYJSON_WRITE_PRETTY |
                    YYJSON_WRITE_ESCAPE_UNICODE |
                    YYJSON_WRITE_ESCAPE_SLASHES |
                    YYJSON_WRITE_ALLOW_INF_AND_NAN);
    return 0;
}
