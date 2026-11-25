#include <stdlib.h>
#include <string.h>
#include <yyjson.h>

#define YYJSON_MERGE_PATCH_MAX_INPUT_SIZE 8192

/* Fuzzer-only allocator cap (not a library limit).
   OSS-Fuzz kills processes above ~2560MB RSS. Valid merge-patch inputs may
   still expand enough to OOM; return NULL before the process is killed. */
#ifndef YYJSON_MERGE_PATCH_FUZZ_ALLOC_LIMIT
#   define YYJSON_MERGE_PATCH_FUZZ_ALLOC_LIMIT (128u * 1024u * 1024u)
#endif

static void *fuzz_malloc(void *ctx, size_t size) {
    (void)ctx;
    if (size > YYJSON_MERGE_PATCH_FUZZ_ALLOC_LIMIT) return NULL;
    return malloc(size);
}

static void *fuzz_realloc(void *ctx, void *ptr, size_t old_size, size_t size) {
    (void)ctx;
    (void)old_size;
    if (size > YYJSON_MERGE_PATCH_FUZZ_ALLOC_LIMIT) return NULL;
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

static void write_and_free_mut_val(yyjson_mut_val *val) {
    char *json;
    if (!val) return;
    json = yyjson_mut_val_write_opts(val, YYJSON_WRITE_NOFLAG, &FUZZ_ALC,
                                     NULL, NULL);
    if (json) FUZZ_ALC.free(FUZZ_ALC.ctx, json);
}

static void run_json_merge_patch(yyjson_doc *base_doc, yyjson_doc *patch_doc) {
    yyjson_val *base_root = yyjson_doc_get_root(base_doc);
    yyjson_val *patch_root = yyjson_doc_get_root(patch_doc);

    if (base_root == NULL || patch_root == NULL) {
        return;
    }

    yyjson_mut_doc *result_doc = yyjson_mut_doc_new(&FUZZ_ALC);
    if (result_doc != NULL) {
        yyjson_mut_val *result =
            yyjson_merge_patch(result_doc, base_root, patch_root);
        write_and_free_mut_val(result);

        yyjson_mut_doc_free(result_doc);
    }

    yyjson_mut_doc *mut_doc = yyjson_mut_doc_new(&FUZZ_ALC);
    if (mut_doc != NULL) {
        yyjson_mut_val *base_mut = yyjson_val_mut_copy(mut_doc, base_root);
        yyjson_mut_val *patch_mut = yyjson_val_mut_copy(mut_doc, patch_root);

        if (base_mut != NULL && patch_mut != NULL) {
            yyjson_mut_val *result =
                yyjson_mut_merge_patch(mut_doc, base_mut, patch_mut);
            write_and_free_mut_val(result);
        }

        yyjson_mut_doc_free(mut_doc);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL ||
        size < sizeof(uint16_t) + 1 ||
        size > YYJSON_MERGE_PATCH_MAX_INPUT_SIZE) {
        return 0;
    }

    uint16_t split_len_raw;
    memcpy(&split_len_raw, data, sizeof(split_len_raw));

    data += sizeof(split_len_raw);
    size -= sizeof(split_len_raw);

    size_t base_size = split_len_raw % (size + 1);
    size_t patch_size = size - base_size;

    const uint8_t *base_data = data;
    const uint8_t *patch_data = data + base_size;

    yyjson_read_flag flags =
        YYJSON_READ_ALLOW_INVALID_UNICODE |
        YYJSON_READ_ALLOW_COMMENTS;

    yyjson_doc *base_doc =
        yyjson_read_opts((char *)(void *)base_data, base_size, flags,
                         &FUZZ_ALC, NULL);
    yyjson_doc *patch_doc =
        yyjson_read_opts((char *)(void *)patch_data, patch_size, flags,
                         &FUZZ_ALC, NULL);

    if (base_doc != NULL && patch_doc != NULL) {
        run_json_merge_patch(base_doc, patch_doc);
    }

    yyjson_doc_free(base_doc);
    yyjson_doc_free(patch_doc);

    return 0;
}
