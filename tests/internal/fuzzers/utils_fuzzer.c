#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <msgpack.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_uri.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* We need a bit of data in this fuzzer */
    if (size < 600) {
        return 0;
    }

    /* Prepare a general null-terminated string */
    char *null_terminated = (char*)malloc(size+1);
    null_terminated[size] = '\0';
    memcpy(null_terminated, data, size);

    /* Fuzzing of flb_utils.c */
    int sec;
    long nsec;
    size_t new_size;
    char *prot    = NULL;
    char *host    = NULL;
    char *port    = NULL;
    char *uri     = NULL;
    char *new_dst = NULL;

    new_dst = (char*)malloc(size * 2);
    flb_utils_write_str_buf(null_terminated, size, &new_dst, &new_size);
    flb_free(new_dst);

    struct mk_list *list = flb_utils_split(null_terminated, 'A', 3);
    if (list != NULL) {
        flb_utils_split_free(list);
    }

    flb_utils_url_split(null_terminated, &prot, &host, &port, &uri);
    flb_utils_size_to_bytes(null_terminated);
    flb_utils_time_split(null_terminated, &sec, &nsec);
    flb_utils_time_to_seconds(null_terminated);
    flb_utils_bool(null_terminated);
    flb_utils_hex2int(null_terminated, size);

    /* Fuzzong of flb_uri.c */
    struct flb_uri *uri2 = NULL;
    uri2 = flb_uri_create(null_terminated);
    if (uri2 != NULL) {
        flb_uri_get(uri2, (int)data[0]);
        flb_uri_dump(uri2);
        flb_uri_destroy(uri2);
    }
    flb_uri_encode((char*)data, size);

    /* Fuzzing of flb_hash.c */
    struct flb_hash *ht = NULL;
    ht = flb_hash_create((int)(data[2] % 0x04),
                         (size_t)data[0],
                         (int)data[1]);
    if (ht != NULL) {
        flb_hash_add(ht, null_terminated, size, null_terminated, size);

        char *out_buf = NULL;
        size_t out_size;
        flb_hash_get(ht, null_terminated, size, (const char **)&out_buf, &out_size);

        /* now let's create some more instances */
        char *instances1[128] = { NULL };
        char *instances2[128] = { NULL };
        for (int i = 0; i < 128; i++) {
            char *in1 = malloc(3);
            char *in2 = malloc(3);
            memcpy(in1, data+(i*4), 2);
            memcpy(in2, data+(i*4)+2, 2);
            in1[2] = '\0';
            in2[2] = '\0';
            flb_hash_add(ht, in1, 2, in2, 2);
            instances1[i] = in1;
            instances2[i] = in2;
        }

        for(int i = 0; i < 20; i++) {
            char *hash_out_buf;
            size_t hash_out_size;
            flb_hash_get_by_id(ht, (int)data[i], (char*)&data[i+1],
                               (const char **)&hash_out_buf, &hash_out_size);
        }

        flb_hash_destroy(ht);
        for (int i =0; i<128; i++) {
            flb_free(instances1[i]);
            flb_free(instances2[i]);
        }
    }

    /* Fuzzing of flb_gzip.c */
    void *str = NULL;
    size_t len;
    void *out_data = NULL;
    size_t out_len;
    if (flb_gzip_compress((char*)data, size, &str, &len) != -1) {
        flb_gzip_uncompress(str, len, &out_data, &out_len);
    }
    if (str != NULL) {
        free(str);
    }
    if (out_data != NULL) {
        free(out_data);
    }
    void *out_data2 = NULL;
    size_t out2_len;
    flb_gzip_uncompress((char*)data, size, &out_data2, &out2_len);
    if (out_data2 != NULL) {
        flb_free(out_data2);
    }

    /* General cleanup */
    flb_free(null_terminated);
    return 0;
}
