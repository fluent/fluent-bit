#include <stdint.h>
#include <fluent-bit/flb_mem.h>
#include <ctraces/ctraces.h>
#include <ctraces/ctr_decode_msgpack.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    size_t off = 0;
    struct ctrace *ctr = NULL;
    struct ctrace *ctr2 = NULL;
    size_t msgpack_text_size;
    char *msgpack_text_buffer = NULL;

    /* Set fuzzer-malloc chance of failure */
    flb_malloc_p = 0;
    flb_malloc_mod = 25000;

    ctr_decode_msgpack_create(&ctr, data, size, &off);
    if (ctr != NULL) {
        ctr_encode_msgpack_create(ctr, &msgpack_text_buffer, &msgpack_text_size);
        ctr_encode_msgpack_destroy(msgpack_text_buffer);

        ctr_destroy(ctr);
    }

    /* Target opentelemtry decoding */
    ctr_decode_opentelemetry_create(&ctr2, data, size, &off);
    if (ctr2 != NULL) {
        ctr_destroy(ctr2);
    }

    return 0;
}
