#include <stdint.h>
#include <stdlib.h>
#include <msgpack.h>
#include <fluent-bit/flb_pack.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    /* Set flb_malloc_mod to be fuzzer-data dependent */
    if (size < 4) {
        return 0;
    }
    flb_malloc_p = 0;
    flb_malloc_mod = *(int*)data;
    data += 4;
    size -= 4;

    /* Avoid division by zero for modulo operations */
    if (flb_malloc_mod == 0) {
        flb_malloc_mod = 1;
    }

    if (size != 512)
        return 0;

    /* target the conversion of raw msgpack to json */
    flb_sds_t record;
    record = flb_msgpack_raw_to_json_sds(data, size, FLB_TRUE);
    flb_sds_destroy(record);

    return 0;
}
