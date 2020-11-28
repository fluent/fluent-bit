#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <msgpack.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_uri.h>
#include <fluent-bit/flb_sha512.h>
#include <fluent-bit/flb_regex.h>

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

    if (flb_utils_write_str_buf(null_terminated, size, &new_dst, &new_size) == 0) {
        flb_free(new_dst);
    }

    struct mk_list *list = flb_utils_split(null_terminated, 'A', 3);
    if (list != NULL) {
        flb_utils_split_free(list);
    }

    if (flb_utils_url_split(null_terminated, &prot, &host, &port, &uri) == 0) {
        flb_free(prot);
        flb_free(port);
        flb_free(host);
        flb_free(uri);
    }

    char *split_protocol;
    char *split_username;
    char *split_password;
    char *split_host;
    char *split_port;
    if (flb_utils_proxy_url_split(null_terminated, &split_protocol,
            split_username, split_password, split_host, split_port) == 0) {
        flb_free(split_protocol);
        flb_free(split_username);
        flb_free(split_password);
        flb_free(split_host);
        flb_free(split_port);
    }


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
    flb_sds_t encoded = flb_uri_encode((char*)data, size);
    if (encoded != NULL) {
        flb_sds_destroy(encoded);
    }

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

    /* sds */
    flb_sds_t fs = flb_sds_create_len((const char*)data, size);
    if (fs != NULL) {
        fs = flb_sds_cat_esc(fs, "AAABBBCCC", 9, "ABC", 3);
        if (fs != NULL) {
            flb_sds_destroy(fs);
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
    int uncompress_ret = flb_gzip_uncompress((char*)data, size, &out_data2, &out2_len);
    if (uncompress_ret != -1 && out_data2 != NULL) {
        flb_free(out_data2);
    }

    /* Fuzzing the sha routines */
    struct flb_sha512 sha512;
    uint8_t buf[64];
    flb_sha512_init(&sha512);
    flb_sha512_update(&sha512, null_terminated, 32);
    flb_sha512_update(&sha512, null_terminated+32, 32);
    flb_sha512_update(&sha512, null_terminated+64, 32);
    flb_sha512_sum(&sha512, buf);


    /* regex */
    char *pregex = "^(?<INT>[^ ]+) (?<FLOAT>[^ ]+) (?<BOOL>[^ ]+) (?<STRING>.+)$";
    flb_regex_init();
    struct flb_regex *freg = flb_regex_create(pregex);
    if (freg != NULL) {
        struct flb_regex_search res;
        flb_regex_match(freg, null_terminated, size);
        flb_regex_destroy(freg);
    }
    flb_regex_exit();

    /* slist */
    struct mk_list list3;
    flb_slist_create(&list3);
    flb_sds_t slist_str = flb_sds_create_len((const char*)data, size);
    flb_slist_add_sds(&list3, slist_str);
    flb_slist_entry_get(&list3, 100);
    flb_slist_dump(&list3);
    flb_slist_destroy(&list3);


    /* General cleanup */
    flb_free(null_terminated);
    return 0;
}
