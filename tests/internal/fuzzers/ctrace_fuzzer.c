#include <stdint.h>
#include <ctraces/ctraces.h>
#include <ctraces/ctr_decode_msgpack.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    size_t off;
    struct ctrace *ctr = NULL;
    ctr_decode_msgpack_create(&ctr, data, size, &off);
    if (ctr != NULL) {
        ctr_destroy(ctr);
    }
    return 0;
}
