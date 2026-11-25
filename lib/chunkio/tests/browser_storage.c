/* ChunkIO browser filesystem regression. SPDX-License-Identifier: Apache-2.0 */

#include <chunkio/chunkio.h>
#include <chunkio/cio_chunk.h>
#include <chunkio/cio_meta.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_utils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ROOT "/storage/chunkio-regression"
#define FILE_PATH ROOT "/events/recovery.flb"
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "Storage check failed at %d: %s\n", __LINE__, #condition); abort(); \
} } while (0)

static void exercise(int restore)
{
    struct cio_options options;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    char block[8192];
    char *data;
    char *metadata;
    FILE *outside;
    size_t size;
    size_t index;
    int metadata_size;
    int error;

    CHECK((access(FILE_PATH, F_OK) == 0) == restore);
    cio_options_init(&options);
    options.root_path = ROOT;
    options.flags = CIO_CHECKSUM | CIO_FULL_SYNC;
    ctx = cio_create(&options);
    CHECK(ctx != NULL);
    stream = cio_stream_create(ctx, "events", CIO_STORE_FS);
    CHECK(stream != NULL);
    chunk = cio_chunk_open(ctx, stream, "recovery.flb", CIO_OPEN_RW, 128, &error);
    CHECK(chunk != NULL);
    if (!restore) {
        CHECK(cio_meta_write(chunk, "browser.logs", 12) == 0);
        for (index = 0; index < 24; index++) {
            memset(block, 'A' + index, sizeof(block));
            CHECK(cio_chunk_write(chunk, block, sizeof(block)) == 0);
        }
        CHECK(cio_chunk_sync(chunk) == 0);
        CHECK(cio_chunk_down(chunk) == 0);
        CHECK(cio_chunk_up(chunk) == 0);
    }
    CHECK(cio_meta_read(chunk, &metadata, &metadata_size) == 0);
    CHECK(metadata_size == 12 && memcmp(metadata, "browser.logs", 12) == 0);
    CHECK(cio_chunk_get_content(chunk, &data, &size) == 0);
    CHECK(size == 24 * sizeof(block));
    for (index = 0; index < size; index++) {
        CHECK(data[index] == 'A' + index / sizeof(block));
    }
    cio_chunk_close(chunk, restore ? CIO_TRUE : CIO_FALSE);
    cio_destroy(ctx);
    if (restore) {
        outside = fopen("/tmp/chunkio-delete-sentinel", "w");
        CHECK(outside != NULL);
        CHECK(fclose(outside) == 0);
        CHECK(symlink("/tmp/chunkio-delete-sentinel", ROOT "/outside") == 0);
        CHECK(symlink(ROOT, ROOT "/cycle") == 0);
        CHECK(cio_utils_recursive_delete(ROOT) == 0);
        CHECK(access("/tmp/chunkio-delete-sentinel", F_OK) == 0);
        CHECK(unlink("/tmp/chunkio-delete-sentinel") == 0);
        CHECK(access(FILE_PATH, F_OK) != 0);
    }
}

int main(int argc, char **argv)
{
    if (argc == 1) {
        exercise(0);
        exercise(1);
    }
    else if (strcmp(argv[1], "write") == 0) {
        exercise(0);
    }
    else if (strcmp(argv[1], "restore") == 0) {
        exercise(1);
    }
    else {
        CHECK(strcmp(argv[1], "empty") == 0);
        CHECK(access(FILE_PATH, F_OK) != 0);
    }
    puts("WASM ChunkIO storage passed: growth, sync, metadata, reopen, deletion");
    return 0;
}
