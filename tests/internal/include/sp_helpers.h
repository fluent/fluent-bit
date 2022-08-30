#ifndef FLB_TEST_SP_HELPERS
#define FLB_TEST_SP_HELPERS

#define MP_UOK MSGPACK_UNPACK_SUCCESS

struct task_check {
    int id;                /* Test identifier */
    int window_type;       /* Type of window in window-based queries */
    int window_size_sec;   /* Size of the window in window-based queries */
    int window_hop_sec;    /* Hopping size in hopping window */
    char *name;            /* Name of the test */
    char *exec;            /* Query */
    void (*cb_check)(int, struct task_check *, char *, size_t);
                           /* Callback function:
                              id, test_check, output buffer, buffer_size */
};

/* Helper functions */
static int mp_count_rows(char *buf, size_t size)
{
    int total = 0;
    size_t off = 0;
    msgpack_unpacked result;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, buf, size, &off) == MP_UOK) {
        total++;
    }

    msgpack_unpacked_destroy(&result);
    return total;
}

/* Count total number of keys considering all rows */
static int mp_count_keys(char *buf, size_t size)
{
    int keys = 0;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, buf, size, &off) == MP_UOK) {
        root = result.data;
        map = root.via.array.ptr[1];
        keys += map.via.map.size;
    }
    msgpack_unpacked_destroy(&result);

    return keys;
}

static inline int float_cmp(double f1, double f2)
{
    double precision = 0.00001;

    if (((f1 - precision) < f2) &&
        ((f1 + precision) > f2)) {
        return 1;
    }
    else {
        return 0;
    }
}

/* Lookup record/row number 'id' and check that 'key' matches 'val' */
static int mp_record_key_cmp(char *buf, size_t size,
                             int record_id, char *key,
                             int val_type, char *val_str, int64_t val_int64,
                             double val_f64)
{
    int i;
    int ret = FLB_FALSE;
    int id = 0;
    int k_len;
    int v_len;
    int keys = 0;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;
    msgpack_object k;
    msgpack_object v;

    k_len = strlen(key);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, buf, size, &off) == MP_UOK) {
        if (id != record_id) {
            id++;
            continue;
        }

        root = result.data;
        map = root.via.array.ptr[1];
        keys += map.via.map.size;

        for (i = 0; i < keys; i++) {
            k = map.via.map.ptr[i].key;
            v = map.via.map.ptr[i].val;

            if (k.type != MSGPACK_OBJECT_STR) {
                continue;
            }

            if (k.via.str.size != k_len) {
                continue;
            }

            if (strncmp(k.via.str.ptr, key, k_len) != 0) {
                continue;
            }

            /* at this point the key matched, now validate the expected value */
            if (val_type == MSGPACK_OBJECT_FLOAT) {
                if (v.type != MSGPACK_OBJECT_FLOAT32 &&
                    v.type != MSGPACK_OBJECT_FLOAT) {
                    msgpack_unpacked_destroy(&result);
                    return FLB_FALSE;
                }
            }
            else if (v.type != val_type) {
                msgpack_unpacked_destroy(&result);
                return FLB_FALSE;
            }

            switch (val_type) {
            case MSGPACK_OBJECT_STR:
                v_len = strlen(val_str);
                if (strncmp(v.via.str.ptr, val_str, v_len) == 0) {
                    ret = FLB_TRUE;
                }
                goto exit;
            case MSGPACK_OBJECT_POSITIVE_INTEGER:
                if (v.via.i64 == val_int64) {
                    ret = FLB_TRUE;
                }
                goto exit;
            case MSGPACK_OBJECT_FLOAT:
                if (float_cmp(v.via.f64, val_f64)) {
                    ret = FLB_TRUE;
                }
                else {
                    printf("double mismatch: %f exp %f\n",
                           v.via.f64, val_f64);
                }
                goto exit;
            };
        }
    }

exit:
    msgpack_unpacked_destroy(&result);
    return ret;
}

#endif
